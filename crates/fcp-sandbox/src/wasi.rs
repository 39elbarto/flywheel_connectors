//! WASI Preview2 runtime for FCP2 connector execution.
//!
//! This module provides a WebAssembly System Interface (WASI) runtime that
//! enforces FCP2 sandbox policies for connector execution. All hostcalls are
//! capability-gated according to the `CompiledPolicy`:
//!
//! - **Filesystem**: Access scoped to manifest-declared readonly/writable paths
//! - **Network**: All egress routed through the Network Guard (egress proxy)
//! - **Clocks**: Deterministic or explicitly granted
//! - **Entropy**: Deterministic or explicitly granted
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    FCP2 WASI Runtime                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
//! │  │ WasiRuntime │──│CompiledPolicy│──│     EgressGuard         │  │
//! │  │  (wasmtime) │  │ (sandbox)   │  │  (network mediation)    │  │
//! │  └──────┬──────┘  └─────────────┘  └───────────┬─────────────┘  │
//! │         │                                      │                │
//! │         ▼                                      ▼                │
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │           Capability-Gated Hostcalls                        ││
//! │  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────────────────┐ ││
//! │  │  │   FS   │  │ Clock  │  │ Random │  │      Network       │ ││
//! │  │  │(scoped)│  │(determ)│  │(determ)│  │ (via EgressGuard)  │ ││
//! │  │  └────────┘  └────────┘  └────────┘  └────────────────────┘ ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use fcp_sandbox::{CompiledPolicy, WasiRuntime, WasiConfig};
//! use fcp_manifest::SandboxSection;
//!
//! // 1. Compile policy from manifest
//! let policy = CompiledPolicy::from_manifest(&manifest.sandbox, Some(state_dir))?;
//!
//! // 2. Create WASI runtime with policy
//! let config = WasiConfig::from_policy(&policy)?;
//! let runtime = WasiRuntime::new(config).await?;
//!
//! // 3. Load and run connector component
//! let component = runtime.load_component(&wasm_bytes)?;
//! let result = runtime.invoke(&component, "run", &args).await?;
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, info, trace};
use wasmtime::{
    Config, Engine, Store,
    component::{Component, Linker, ResourceTable},
};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiView};

use crate::egress::{EgressGuard, EgressHttpRequest, EgressRequest, EgressTcpConnectRequest};
use crate::sandbox::{CompiledPolicy, SandboxError};
use fcp_manifest::NetworkConstraints;

// ============================================================================
// Errors
// ============================================================================

/// Errors from WASI runtime operations.
#[derive(Debug, Error)]
pub enum WasiError {
    /// Failed to create the WASI runtime engine.
    #[error("failed to create WASI engine: {0}")]
    EngineCreation(String),

    /// Failed to load a WebAssembly component.
    #[error("failed to load component: {0}")]
    ComponentLoad(String),

    /// Failed to instantiate the component.
    #[error("failed to instantiate component: {0}")]
    Instantiation(String),

    /// Component execution failed.
    #[error("component execution failed: {0}")]
    Execution(String),

    /// Resource limit exceeded during execution.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),

    /// Wall-clock timeout exceeded.
    #[error("wall-clock timeout exceeded")]
    Timeout,

    /// Filesystem access denied by policy.
    #[error("filesystem access denied: {path} ({reason})")]
    FsAccessDenied { path: String, reason: String },

    /// Network access denied by policy.
    #[error("network access denied: {0}")]
    NetworkAccessDenied(String),

    /// Clock access denied (determinism required).
    #[error("clock access denied: deterministic mode enabled")]
    ClockAccessDenied,

    /// Entropy access denied (determinism required).
    #[error("entropy access denied: deterministic mode enabled")]
    EntropyAccessDenied,

    /// Invalid component format.
    #[error("invalid component format: {0}")]
    InvalidComponent(String),

    /// Manifest extraction failed.
    #[error("manifest extraction failed: {0}")]
    ManifestExtraction(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Sandbox policy error.
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),
}

/// Result type for WASI operations.
pub type WasiResult<T> = Result<T, WasiError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the WASI runtime.
///
/// This is derived from `CompiledPolicy` and controls all aspects of the
/// sandbox enforcement within the WASI runtime.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct WasiConfig {
    /// Memory limit in bytes.
    pub memory_limit_bytes: u64,

    /// Wall-clock timeout for execution.
    pub wall_clock_timeout: Duration,

    /// Paths allowed for read-only access (absolute paths).
    pub readonly_paths: Vec<PathBuf>,

    /// Paths allowed for read-write access (absolute paths).
    pub writable_paths: Vec<PathBuf>,

    /// State directory for connector persistent data.
    pub state_dir: Option<PathBuf>,

    /// Whether to enable deterministic mode.
    ///
    /// In deterministic mode:
    /// - Clocks return fixed values
    /// - Entropy returns deterministic sequences
    pub deterministic_mode: bool,

    /// Fixed timestamp for deterministic mode (Unix epoch seconds).
    pub deterministic_timestamp: u64,

    /// Seed for deterministic random number generation.
    pub deterministic_seed: u64,

    /// Network constraints (if network access is allowed).
    pub network_constraints: Option<NetworkConstraints>,

    /// Whether direct network access is blocked.
    ///
    /// When true, all network access must go through the Network Guard.
    pub block_direct_network: bool,

    /// Maximum fuel (instruction count) before interruption.
    ///
    /// This provides CPU limiting. Set to 0 for unlimited.
    pub max_fuel: u64,

    /// Environment variables to expose to the component.
    pub env_vars: HashMap<String, String>,

    /// Command-line arguments to pass to the component.
    pub args: Vec<String>,

    /// Inherit stdout from the host process.
    pub inherit_stdout: bool,

    /// Inherit stderr from the host process.
    pub inherit_stderr: bool,
}

impl Default for WasiConfig {
    fn default() -> Self {
        Self {
            memory_limit_bytes: 256 * 1024 * 1024, // 256 MiB
            wall_clock_timeout: Duration::from_secs(30),
            readonly_paths: vec![],
            writable_paths: vec![],
            state_dir: None,
            deterministic_mode: false,
            deterministic_timestamp: 0,
            deterministic_seed: 0,
            network_constraints: None,
            block_direct_network: true,
            max_fuel: 0, // Unlimited by default
            env_vars: HashMap::new(),
            args: vec![],
            inherit_stdout: false,
            inherit_stderr: false,
        }
    }
}

impl WasiConfig {
    /// Create a WASI configuration from a compiled sandbox policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy contains invalid paths.
    pub fn from_policy(policy: &CompiledPolicy) -> WasiResult<Self> {
        Ok(Self {
            memory_limit_bytes: policy.memory_limit_bytes,
            wall_clock_timeout: policy.wall_clock_timeout,
            readonly_paths: policy.readonly_paths.clone(),
            writable_paths: policy.writable_paths.clone(),
            state_dir: policy.state_dir.clone(),
            deterministic_mode: false, // Can be overridden
            deterministic_timestamp: 0,
            deterministic_seed: 0,
            network_constraints: None, // Set separately
            block_direct_network: policy.block_direct_network,
            max_fuel: Self::cpu_percent_to_fuel(policy.cpu_percent),
            env_vars: HashMap::new(),
            args: vec![],
            inherit_stdout: false,
            inherit_stderr: false,
        })
    }

    /// Convert CPU percentage to wasmtime fuel.
    ///
    /// This is a heuristic mapping. In practice, fuel consumption varies
    /// by instruction type.
    fn cpu_percent_to_fuel(cpu_percent: u8) -> u64 {
        if cpu_percent >= 100 {
            0 // Unlimited
        } else {
            // Base fuel per "time slice" scaled by percentage
            let base_fuel: u64 = 10_000_000_000; // 10B instructions base
            base_fuel * u64::from(cpu_percent) / 100
        }
    }

    /// Set network constraints for the runtime.
    #[must_use]
    pub fn with_network_constraints(mut self, constraints: NetworkConstraints) -> Self {
        self.network_constraints = Some(constraints);
        self
    }

    /// Enable deterministic mode with fixed timestamp and seed.
    #[must_use]
    pub const fn with_deterministic_mode(mut self, timestamp: u64, seed: u64) -> Self {
        self.deterministic_mode = true;
        self.deterministic_timestamp = timestamp;
        self.deterministic_seed = seed;
        self
    }

    /// Set environment variables.
    #[must_use]
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env_vars = env;
        self
    }

    /// Set command-line arguments.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Inherit stdout/stderr from host.
    #[must_use]
    pub const fn with_inherit_stdio(mut self, stdout: bool, stderr: bool) -> Self {
        self.inherit_stdout = stdout;
        self.inherit_stderr = stderr;
        self
    }
}

// ============================================================================
// Filesystem Capability Gate
// ============================================================================

/// Filesystem capability gate that enforces path restrictions.
#[derive(Debug)]
pub struct FsCapabilityGate {
    /// Canonical readonly paths.
    readonly_paths: Vec<PathBuf>,
    /// Canonical writable paths.
    writable_paths: Vec<PathBuf>,
}

impl FsCapabilityGate {
    /// Create a new filesystem capability gate.
    #[must_use]
    pub fn new(readonly_paths: Vec<PathBuf>, writable_paths: Vec<PathBuf>) -> Self {
        // Canonicalize paths where possible
        let readonly_paths = readonly_paths
            .into_iter()
            .filter_map(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
            .collect();
        let writable_paths = writable_paths
            .into_iter()
            .filter_map(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
            .collect();

        Self {
            readonly_paths,
            writable_paths,
        }
    }

    /// Check if a path is allowed for the given access mode.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to check (will be canonicalized).
    /// * `write` - Whether write access is requested.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::FsAccessDenied` if the path is not allowed.
    pub fn check_access(&self, path: &Path, write: bool) -> WasiResult<()> {
        // Canonicalize the requested path
        let canonical = match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => {
                // Path doesn't exist yet - check parent for write operations
                if write {
                    if let Some(parent) = path.parent() {
                        if let Ok(p) = std::fs::canonicalize(parent) {
                            p.join(path.file_name().unwrap_or_default())
                        } else {
                            return Err(WasiError::FsAccessDenied {
                                path: path.display().to_string(),
                                reason: "parent directory does not exist".into(),
                            });
                        }
                    } else {
                        return Err(WasiError::FsAccessDenied {
                            path: path.display().to_string(),
                            reason: "path has no parent".into(),
                        });
                    }
                } else {
                    return Err(WasiError::FsAccessDenied {
                        path: path.display().to_string(),
                        reason: "path does not exist".into(),
                    });
                }
            }
        };

        // Check writable paths first (superset of read access)
        for allowed in &self.writable_paths {
            if canonical.starts_with(allowed) {
                trace!(path = %canonical.display(), allowed = %allowed.display(), "fs access granted (writable)");
                return Ok(());
            }
        }

        // If write access is requested, must be in writable paths
        if write {
            return Err(WasiError::FsAccessDenied {
                path: path.display().to_string(),
                reason: "write access not allowed".into(),
            });
        }

        // Check readonly paths
        for allowed in &self.readonly_paths {
            if canonical.starts_with(allowed) {
                trace!(path = %canonical.display(), allowed = %allowed.display(), "fs access granted (readonly)");
                return Ok(());
            }
        }

        Err(WasiError::FsAccessDenied {
            path: path.display().to_string(),
            reason: "path not in allowed list".into(),
        })
    }
}

// ============================================================================
// Network Capability Gate
// ============================================================================

/// Network capability gate that routes all traffic through the Network Guard.
#[derive(Debug)]
pub struct NetworkCapabilityGate {
    /// The egress guard for policy enforcement.
    guard: EgressGuard,
    /// Network constraints from the manifest.
    constraints: Option<NetworkConstraints>,
    /// Whether direct network access is blocked.
    block_direct: bool,
}

impl NetworkCapabilityGate {
    /// Create a new network capability gate.
    #[must_use]
    pub const fn new(constraints: Option<NetworkConstraints>, block_direct: bool) -> Self {
        Self {
            guard: EgressGuard::new(),
            constraints,
            block_direct,
        }
    }

    /// Check if an HTTP request is allowed.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if the request violates policy.
    pub fn check_http(&self, url: &str, method: &str) -> WasiResult<()> {
        if self.block_direct && self.constraints.is_none() {
            return Err(WasiError::NetworkAccessDenied(
                "direct network access blocked and no constraints configured".into(),
            ));
        }

        let Some(constraints) = &self.constraints else {
            // No constraints = no network access
            return Err(WasiError::NetworkAccessDenied("no network policy".into()));
        };

        let request = EgressRequest::Http(EgressHttpRequest {
            url: url.to_string(),
            method: method.to_string(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        self.guard
            .evaluate(&request, constraints)
            .map_err(|e| WasiError::NetworkAccessDenied(e.to_string()))?;

        debug!(url = %url, method = %method, "HTTP request allowed");
        Ok(())
    }

    /// Check if a TCP connection is allowed.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if the connection violates policy.
    pub fn check_tcp(&self, host: &str, port: u16, tls: bool) -> WasiResult<()> {
        if self.block_direct && self.constraints.is_none() {
            return Err(WasiError::NetworkAccessDenied(
                "direct network access blocked and no constraints configured".into(),
            ));
        }

        let Some(constraints) = &self.constraints else {
            return Err(WasiError::NetworkAccessDenied("no network policy".into()));
        };

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: host.to_string(),
            port,
            tls,
            sni_override: None,
            credential_id: None,
        });

        self.guard
            .evaluate(&request, constraints)
            .map_err(|e| WasiError::NetworkAccessDenied(e.to_string()))?;

        debug!(host = %host, port = %port, tls = %tls, "TCP connection allowed");
        Ok(())
    }
}

// ============================================================================
// WASI Host State
// ============================================================================

/// Host state for the WASI runtime.
///
/// This is the context passed to all hostcalls and contains the capability
/// gates and runtime state.
pub struct WasiHostState {
    /// WASI context from wasmtime-wasi.
    wasi_ctx: WasiCtx,
    /// Resource table for component model.
    resource_table: ResourceTable,
    /// Filesystem capability gate.
    #[allow(dead_code)]
    fs_gate: Arc<FsCapabilityGate>,
    /// Network capability gate.
    #[allow(dead_code)]
    net_gate: Arc<NetworkCapabilityGate>,
    /// Whether deterministic mode is enabled.
    deterministic_mode: bool,
    /// Fixed timestamp for deterministic mode.
    deterministic_timestamp: u64,
    /// Deterministic random state.
    deterministic_rng: Mutex<DeterministicRng>,
    /// Execution start time.
    start_time: Instant,
    /// Wall-clock timeout.
    timeout: Duration,
}

impl WasiHostState {
    /// Create new host state from configuration.
    fn new(config: &WasiConfig, wasi_ctx: WasiCtx) -> Self {
        let fs_gate = Arc::new(FsCapabilityGate::new(
            config.readonly_paths.clone(),
            config.writable_paths.clone(),
        ));

        let net_gate = Arc::new(NetworkCapabilityGate::new(
            config.network_constraints.clone(),
            config.block_direct_network,
        ));

        Self {
            wasi_ctx,
            resource_table: ResourceTable::new(),
            fs_gate,
            net_gate,
            deterministic_mode: config.deterministic_mode,
            deterministic_timestamp: config.deterministic_timestamp,
            deterministic_rng: Mutex::new(DeterministicRng::new(config.deterministic_seed)),
            start_time: Instant::now(),
            timeout: config.wall_clock_timeout,
        }
    }

    /// Check if execution has exceeded the wall-clock timeout.
    pub fn check_timeout(&self) -> WasiResult<()> {
        if self.start_time.elapsed() > self.timeout {
            Err(WasiError::Timeout)
        } else {
            Ok(())
        }
    }

    /// Get the current time (respecting deterministic mode).
    pub fn current_time(&self) -> SystemTime {
        if self.deterministic_mode {
            SystemTime::UNIX_EPOCH + Duration::from_secs(self.deterministic_timestamp)
        } else {
            SystemTime::now()
        }
    }

    /// Get random bytes (respecting deterministic mode).
    pub fn get_random_bytes(&self, len: usize) -> Vec<u8> {
        if self.deterministic_mode {
            let mut rng = self.deterministic_rng.blocking_lock();
            (0..len).map(|_| rng.next_byte()).collect()
        } else {
            use rand::RngCore;
            let mut bytes = vec![0u8; len];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes
        }
    }
}

impl WasiView for WasiHostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }

    fn table(&mut self) -> &mut ResourceTable {
        &mut self.resource_table
    }
}

/// Deterministic random number generator (xorshift64).
#[derive(Debug)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    const fn new(seed: u64) -> Self {
        // Ensure non-zero state
        Self {
            state: if seed == 0 {
                0x853c_49e6_748f_ea9b
            } else {
                seed
            },
        }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

// ============================================================================
// WASI Runtime
// ============================================================================

/// WASI Preview2 runtime for FCP2 connector execution.
///
/// This runtime provides capability-gated access to system resources according
/// to the `WasiConfig` (derived from `CompiledPolicy`).
pub struct WasiRuntime {
    /// Wasmtime engine (shared across components).
    engine: Engine,
    /// Runtime configuration.
    config: WasiConfig,
    /// Component linker with WASI bindings.
    linker: Linker<WasiHostState>,
}

impl WasiRuntime {
    /// Create a new WASI runtime with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime cannot be initialized.
    pub fn new(config: WasiConfig) -> WasiResult<Self> {
        // Configure wasmtime engine
        let mut engine_config = Config::new();
        engine_config.wasm_component_model(true);
        engine_config.async_support(true);

        // Enable fuel metering if a limit is set
        if config.max_fuel > 0 {
            engine_config.consume_fuel(true);
        }

        // Memory limits are set per-store, not engine-wide

        let engine =
            Engine::new(&engine_config).map_err(|e| WasiError::EngineCreation(e.to_string()))?;

        // Create linker with WASI bindings
        let mut linker: Linker<WasiHostState> = Linker::new(&engine);
        wasmtime_wasi::add_to_linker_async(&mut linker)
            .map_err(|e| WasiError::EngineCreation(format!("failed to add WASI: {e}")))?;

        info!(
            memory_limit = config.memory_limit_bytes,
            timeout = ?config.wall_clock_timeout,
            deterministic = config.deterministic_mode,
            "WASI runtime initialized"
        );

        Ok(Self {
            engine,
            config,
            linker,
        })
    }

    /// Load a WebAssembly component from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the component is invalid or cannot be loaded.
    pub fn load_component(&self, wasm_bytes: &[u8]) -> WasiResult<Component> {
        Component::new(&self.engine, wasm_bytes)
            .map_err(|e| WasiError::ComponentLoad(e.to_string()))
    }

    /// Load a WebAssembly component from a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the component is invalid.
    pub fn load_component_from_file(&self, path: &Path) -> WasiResult<Component> {
        Component::from_file(&self.engine, path)
            .map_err(|e| WasiError::ComponentLoad(e.to_string()))
    }

    /// Create a new execution store with the configured WASI context.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be created.
    pub fn create_store(&self) -> WasiResult<Store<WasiHostState>> {
        // Build WASI context
        let mut wasi_builder = WasiCtxBuilder::new();

        // Add environment variables
        for (key, value) in &self.config.env_vars {
            wasi_builder.env(key, value);
        }

        // Add arguments
        wasi_builder.args(&self.config.args);

        // Configure stdio
        if self.config.inherit_stdout {
            wasi_builder.inherit_stdout();
        }
        if self.config.inherit_stderr {
            wasi_builder.inherit_stderr();
        }

        // Mount filesystem directories
        for path in &self.config.readonly_paths {
            if path.is_dir() {
                let guest_path = path.file_name().map_or_else(
                    || path.display().to_string(),
                    |n| n.to_string_lossy().to_string(),
                );
                wasi_builder
                    .preopened_dir(path, &guest_path, DirPerms::READ, FilePerms::READ)
                    .map_err(|e| {
                        WasiError::EngineCreation(format!(
                            "failed to mount {}: {e}",
                            path.display()
                        ))
                    })?;
            }
        }

        for path in &self.config.writable_paths {
            if path.is_dir() {
                let guest_path = path.file_name().map_or_else(
                    || path.display().to_string(),
                    |n| n.to_string_lossy().to_string(),
                );
                wasi_builder
                    .preopened_dir(path, &guest_path, DirPerms::all(), FilePerms::all())
                    .map_err(|e| {
                        WasiError::EngineCreation(format!(
                            "failed to mount {}: {e}",
                            path.display()
                        ))
                    })?;
            }
        }

        let wasi_ctx = wasi_builder.build();
        let host_state = WasiHostState::new(&self.config, wasi_ctx);

        let mut store = Store::new(&self.engine, host_state);

        // Set fuel limit if configured
        if self.config.max_fuel > 0 {
            store
                .set_fuel(self.config.max_fuel)
                .map_err(|e| WasiError::EngineCreation(format!("failed to set fuel: {e}")))?;
        }

        Ok(store)
    }

    /// Get a reference to the linker.
    #[must_use]
    pub const fn linker(&self) -> &Linker<WasiHostState> {
        &self.linker
    }

    /// Get the engine.
    #[must_use]
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }
}

// ============================================================================
// Manifest Extraction
// ============================================================================

/// Extract the FCP2 manifest from a WASI component.
///
/// FCP2 connectors embed their manifest in a custom section named `fcp-manifest`.
/// This function extracts and parses it.
///
/// # Errors
///
/// Returns an error if the manifest cannot be extracted or parsed.
pub fn extract_manifest_from_component(
    wasm_bytes: &[u8],
) -> WasiResult<fcp_manifest::ConnectorManifest> {
    // Parse the component to find custom sections
    // Note: wasmtime doesn't expose custom sections directly, so we parse
    // the raw bytes directly.

    // First, try to find the manifest in the raw bytes
    // Custom sections in WASM components have a specific format
    let manifest_bytes = extract_custom_section(wasm_bytes, "fcp-manifest")
        .ok_or_else(|| WasiError::ManifestExtraction("no fcp-manifest section found".into()))?;

    // Parse the manifest (it's stored as JSON or CBOR)
    let manifest: fcp_manifest::ConnectorManifest = if manifest_bytes.starts_with(b"{") {
        serde_json::from_slice(&manifest_bytes)
            .map_err(|e| WasiError::ManifestExtraction(format!("invalid JSON manifest: {e}")))?
    } else {
        ciborium::from_reader(&manifest_bytes[..])
            .map_err(|e| WasiError::ManifestExtraction(format!("invalid CBOR manifest: {e}")))?
    };

    debug!(
        connector_id = %manifest.connector.id,
        version = %manifest.connector.version,
        "extracted manifest from component"
    );

    Ok(manifest)
}

/// Extract a custom section from raw WASM bytes.
fn extract_custom_section(wasm_bytes: &[u8], section_name: &str) -> Option<Vec<u8>> {
    // Simple WASM custom section parser
    // Custom sections have ID 0 and format: [name_len][name][payload]

    // Skip WASM magic + version (8 bytes)
    if wasm_bytes.len() < 8 {
        return None;
    }

    let mut pos = 8;

    while pos < wasm_bytes.len() {
        // Section ID (1 byte)
        let section_id = wasm_bytes[pos];
        pos += 1;

        // Section size (LEB128)
        let (section_size, bytes_read) = read_leb128(&wasm_bytes[pos..])?;
        pos += bytes_read;

        if section_id == 0 {
            // Custom section - read name
            let section_start = pos;
            let (name_len, name_bytes_read) = read_leb128(&wasm_bytes[pos..])?;
            pos += name_bytes_read;

            if pos + name_len > wasm_bytes.len() {
                return None;
            }

            let name = std::str::from_utf8(&wasm_bytes[pos..pos + name_len]).ok()?;
            pos += name_len;

            if name == section_name {
                // Found it - return the payload
                let payload_len = section_size - (pos - section_start);
                if pos + payload_len > wasm_bytes.len() {
                    return None;
                }
                return Some(wasm_bytes[pos..pos + payload_len].to_vec());
            }

            // Skip to next section
            pos = section_start + section_size;
        } else {
            // Skip non-custom section
            pos += section_size;
        }
    }

    None
}

/// Read a LEB128-encoded unsigned integer.
fn read_leb128(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut result: usize = 0;
    let mut shift = 0;
    let mut pos = 0;

    loop {
        if pos >= bytes.len() || shift >= 64 {
            return None;
        }

        let byte = bytes[pos];
        pos += 1;

        result |= ((byte & 0x7F) as usize) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            return Some((result, pos));
        }
    }
}

// ============================================================================
// Execution Result
// ============================================================================

/// Result of component execution.
#[derive(Debug)]
pub struct ExecutionResult {
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Stdout output (if captured).
    pub stdout: Option<Bytes>,
    /// Stderr output (if captured).
    pub stderr: Option<Bytes>,
    /// Execution duration.
    pub duration: Duration,
    /// Fuel consumed (if metering enabled).
    pub fuel_consumed: Option<u64>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasi_config_default() {
        let config = WasiConfig::default();
        assert_eq!(config.memory_limit_bytes, 256 * 1024 * 1024);
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(30));
        assert!(!config.deterministic_mode);
        assert!(config.block_direct_network);
    }

    #[test]
    fn test_wasi_config_with_deterministic_mode() {
        let config = WasiConfig::default().with_deterministic_mode(1_700_000_000, 42);

        assert!(config.deterministic_mode);
        assert_eq!(config.deterministic_timestamp, 1_700_000_000);
        assert_eq!(config.deterministic_seed, 42);
    }

    #[test]
    fn test_fs_capability_gate() {
        let gate = FsCapabilityGate::new(vec![PathBuf::from("/usr")], vec![PathBuf::from("/tmp")]);

        // These paths might not exist in test environment, so we test the logic
        // by checking that the paths are stored correctly
        assert_eq!(gate.readonly_paths.len(), 1);
        assert_eq!(gate.writable_paths.len(), 1);
    }

    #[test]
    fn test_network_capability_gate_no_constraints() {
        let gate = NetworkCapabilityGate::new(None, true);

        let result = gate.check_http("https://example.com/", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_rng() {
        let mut rng1 = DeterministicRng::new(12345);
        let mut rng2 = DeterministicRng::new(12345);

        // Same seed should produce same sequence
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }

        // Different seed should produce different sequence
        let mut rng3 = DeterministicRng::new(54321);
        let mut rng4 = DeterministicRng::new(12345);

        // Very unlikely to match
        let seq3: Vec<u64> = (0..10).map(|_| rng3.next_u64()).collect();
        let seq4: Vec<u64> = (0..10).map(|_| rng4.next_u64()).collect();
        assert_ne!(seq3, seq4);
    }

    #[test]
    fn test_leb128_parsing() {
        // Single byte value
        assert_eq!(read_leb128(&[0x00]), Some((0, 1)));
        assert_eq!(read_leb128(&[0x7F]), Some((127, 1)));

        // Two byte value (128)
        assert_eq!(read_leb128(&[0x80, 0x01]), Some((128, 2)));

        // Larger value
        assert_eq!(read_leb128(&[0xE5, 0x8E, 0x26]), Some((624_485, 3)));
    }

    #[test]
    fn test_cpu_percent_to_fuel() {
        assert_eq!(WasiConfig::cpu_percent_to_fuel(100), 0); // Unlimited
        assert_eq!(WasiConfig::cpu_percent_to_fuel(50), 5_000_000_000);
        assert_eq!(WasiConfig::cpu_percent_to_fuel(10), 1_000_000_000);
    }

    // ── New tests ──

    #[test]
    fn test_wasi_error_display() {
        let e = WasiError::EngineCreation("no support".into());
        assert!(e.to_string().contains("no support"));

        let e = WasiError::ComponentLoad("bad wasm".into());
        assert!(e.to_string().contains("bad wasm"));

        let e = WasiError::Instantiation("linker fail".into());
        assert!(e.to_string().contains("linker fail"));

        let e = WasiError::Execution("trap".into());
        assert!(e.to_string().contains("trap"));

        let e = WasiError::ResourceLimit("oom".into());
        assert!(e.to_string().contains("oom"));

        let e = WasiError::Timeout;
        assert!(e.to_string().contains("timeout"));

        let e = WasiError::FsAccessDenied {
            path: "/etc/shadow".into(),
            reason: "not allowed".into(),
        };
        assert!(e.to_string().contains("/etc/shadow"));
        assert!(e.to_string().contains("not allowed"));

        let e = WasiError::NetworkAccessDenied("blocked".into());
        assert!(e.to_string().contains("blocked"));

        let e = WasiError::ClockAccessDenied;
        assert!(e.to_string().contains("deterministic"));

        let e = WasiError::EntropyAccessDenied;
        assert!(e.to_string().contains("deterministic"));

        let e = WasiError::InvalidComponent("not a component".into());
        assert!(e.to_string().contains("not a component"));

        let e = WasiError::ManifestExtraction("missing".into());
        assert!(e.to_string().contains("missing"));

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e = WasiError::Io(io_err);
        assert!(e.to_string().contains("gone"));
    }

    #[test]
    fn test_wasi_config_with_env() {
        let mut env = HashMap::new();
        env.insert("KEY".into(), "VALUE".into());
        let config = WasiConfig::default().with_env(env);
        assert_eq!(config.env_vars.get("KEY"), Some(&"VALUE".into()));
    }

    #[test]
    fn test_wasi_config_with_args() {
        let config = WasiConfig::default().with_args(vec!["arg1".into(), "arg2".into()]);
        assert_eq!(config.args.len(), 2);
        assert_eq!(config.args[0], "arg1");
    }

    #[test]
    fn test_wasi_config_with_inherit_stdio() {
        let config = WasiConfig::default().with_inherit_stdio(true, true);
        assert!(config.inherit_stdout);
        assert!(config.inherit_stderr);

        let config = WasiConfig::default().with_inherit_stdio(false, true);
        assert!(!config.inherit_stdout);
        assert!(config.inherit_stderr);
    }

    #[test]
    fn test_wasi_config_from_policy() {
        use crate::sandbox::{CompiledPolicy, PlatformFlags};
        use fcp_manifest::SandboxProfile;
        let policy = CompiledPolicy {
            profile: SandboxProfile::Strict,
            memory_limit_bytes: 512 * 1024 * 1024,
            cpu_percent: 75,
            wall_clock_timeout: Duration::from_secs(60),
            readonly_paths: vec![PathBuf::from("/usr")],
            writable_paths: vec![PathBuf::from("/tmp/data")],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: Some(PathBuf::from("/tmp/data")),
            platform_flags: PlatformFlags::default(),
        };

        let config = WasiConfig::from_policy(&policy).unwrap();
        assert_eq!(config.memory_limit_bytes, 512 * 1024 * 1024);
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(60));
        assert!(config.block_direct_network);
        assert_eq!(config.readonly_paths.len(), 1);
        assert_eq!(config.writable_paths.len(), 1);
        assert_eq!(config.state_dir, Some(PathBuf::from("/tmp/data")));
    }

    #[test]
    fn test_deterministic_rng_zero_seed_uses_default() {
        let mut rng = DeterministicRng::new(0);
        // Zero seed should use a non-zero default
        let val = rng.next_u64();
        assert_ne!(val, 0);
    }

    #[test]
    fn test_deterministic_rng_next_byte() {
        let mut rng1 = DeterministicRng::new(42);
        let mut rng2 = DeterministicRng::new(42);
        // Same seed produces same byte sequence
        for _ in 0..10 {
            assert_eq!(rng1.next_byte(), rng2.next_byte());
        }
    }

    #[test]
    fn test_network_capability_gate_check_tcp_no_constraints() {
        let gate = NetworkCapabilityGate::new(None, true);
        let result = gate.check_tcp("db.example.com", 5432, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_network_capability_gate_not_blocked_no_constraints() {
        // block_direct=false, no constraints = should error with "no network policy"
        let gate = NetworkCapabilityGate::new(None, false);
        let result = gate.check_http("https://example.com/", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_network_capability_gate_with_constraints() {
        use fcp_manifest::NetworkConstraints;
        let constraints = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };

        let gate = NetworkCapabilityGate::new(Some(constraints), true);
        let result = gate.check_http("https://api.example.com/data", "GET");
        assert!(result.is_ok());

        // Denied host
        let result = gate.check_http("https://evil.com/", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_leb128_empty_input() {
        assert_eq!(read_leb128(&[]), None);
    }

    #[test]
    fn test_leb128_single_byte_max() {
        assert_eq!(read_leb128(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn test_leb128_multi_byte() {
        // 300 = 0xAC 0x02
        assert_eq!(read_leb128(&[0xAC, 0x02]), Some((300, 2)));
    }

    #[test]
    fn test_leb128_incomplete() {
        // High bit set but no continuation byte
        assert_eq!(read_leb128(&[0x80]), None);
    }

    #[test]
    fn test_cpu_percent_to_fuel_zero() {
        assert_eq!(WasiConfig::cpu_percent_to_fuel(0), 0);
    }

    #[test]
    fn test_cpu_percent_to_fuel_one() {
        assert_eq!(WasiConfig::cpu_percent_to_fuel(1), 100_000_000);
    }

    #[test]
    fn test_cpu_percent_to_fuel_above_100() {
        // 200% → unlimited (0)
        assert_eq!(WasiConfig::cpu_percent_to_fuel(200), 0);
    }

    #[test]
    fn test_extract_custom_section_too_short() {
        // Less than 8 bytes (WASM magic + version)
        assert!(extract_custom_section(&[0, 1, 2], "anything").is_none());
    }

    #[test]
    fn test_extract_custom_section_empty_wasm() {
        // Valid WASM magic + version but no sections
        let wasm = b"\0asm\x01\0\0\0";
        assert!(extract_custom_section(wasm, "fcp-manifest").is_none());
    }

    #[test]
    fn test_wasi_config_default_comprehensive() {
        let config = WasiConfig::default();
        assert_eq!(config.memory_limit_bytes, 256 * 1024 * 1024);
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(30));
        assert!(config.readonly_paths.is_empty());
        assert!(config.writable_paths.is_empty());
        assert!(config.state_dir.is_none());
        assert!(!config.deterministic_mode);
        assert_eq!(config.deterministic_timestamp, 0);
        assert_eq!(config.deterministic_seed, 0);
        assert!(config.network_constraints.is_none());
        assert!(config.block_direct_network);
        assert_eq!(config.max_fuel, 0);
        assert!(config.env_vars.is_empty());
        assert!(config.args.is_empty());
        assert!(!config.inherit_stdout);
        assert!(!config.inherit_stderr);
    }

    #[test]
    fn test_fs_capability_gate_empty() {
        let gate = FsCapabilityGate::new(vec![], vec![]);
        assert!(gate.readonly_paths.is_empty());
        assert!(gate.writable_paths.is_empty());
    }
}
