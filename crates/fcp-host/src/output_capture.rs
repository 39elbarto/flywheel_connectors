//! Output capture for supervised connector processes.
//!
//! Provides a fixed-capacity ring buffer for capturing stdout/stderr from
//! child connector processes, with optional structured JSON line parsing.
//!
//! # Design
//!
//! Each connector process gets two ring buffers (stdout, stderr). When the
//! buffer fills, the oldest bytes are overwritten. This keeps memory bounded
//! while always retaining the most recent output for debugging.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Ring buffer
// ─────────────────────────────────────────────────────────────────────────────

/// Fixed-capacity byte ring buffer.
///
/// When full, new bytes overwrite the oldest ones. The buffer always
/// contains the most recent `capacity` bytes.
#[derive(Debug, Clone)]
pub struct RingBuffer {
    data: VecDeque<u8>,
    capacity: usize,
    total_written: u64,
}

impl RingBuffer {
    /// Create a new ring buffer with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            data: VecDeque::with_capacity(capacity),
            capacity,
            total_written: 0,
        }
    }

    /// Write bytes into the buffer.
    ///
    /// If the input exceeds capacity, only the last `capacity` bytes are kept.
    pub fn write(&mut self, bytes: &[u8]) {
        self.total_written += bytes.len() as u64;

        if bytes.len() >= self.capacity {
            // Input alone fills the buffer — take only the tail.
            self.data.clear();
            let start = bytes.len() - self.capacity;
            self.data.extend(&bytes[start..]);
        } else {
            // Evict oldest to make room, then append.
            let needed = (self.data.len() + bytes.len()).saturating_sub(self.capacity);
            if needed > 0 {
                self.data.drain(..needed);
            }
            self.data.extend(bytes);
        }
    }

    /// Get the last `n` bytes as a contiguous slice (via allocation).
    #[must_use]
    pub fn last_n(&self, n: usize) -> Vec<u8> {
        let take = n.min(self.data.len());
        let start = self.data.len() - take;
        self.data.iter().skip(start).copied().collect()
    }

    /// Get all buffered bytes.
    #[must_use]
    pub fn contents(&self) -> Vec<u8> {
        self.data.iter().copied().collect()
    }

    /// Current number of bytes in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Buffer capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Total bytes ever written (including overwritten ones).
    #[must_use]
    pub const fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Whether data has been lost due to overflow.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn has_overflow(&self) -> bool {
        self.total_written > self.capacity as u64
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Output capture
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for output capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputCaptureConfig {
    /// Capacity for stdout ring buffer in bytes.
    pub stdout_capacity: usize,
    /// Capacity for stderr ring buffer in bytes.
    pub stderr_capacity: usize,
    /// Whether to parse JSON lines from stdout.
    pub parse_json_lines: bool,
    /// Maximum number of parsed JSON lines to retain.
    pub max_json_lines: usize,
}

impl Default for OutputCaptureConfig {
    fn default() -> Self {
        Self {
            stdout_capacity: 64 * 1024, // 64 KiB
            stderr_capacity: 64 * 1024,
            parse_json_lines: true,
            max_json_lines: 100,
        }
    }
}

impl OutputCaptureConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set stdout capacity.
    #[must_use]
    pub const fn with_stdout_capacity(mut self, capacity: usize) -> Self {
        self.stdout_capacity = capacity;
        self
    }

    /// Set stderr capacity.
    #[must_use]
    pub const fn with_stderr_capacity(mut self, capacity: usize) -> Self {
        self.stderr_capacity = capacity;
        self
    }

    /// Set JSON line parsing.
    #[must_use]
    pub const fn with_json_parsing(mut self, enabled: bool) -> Self {
        self.parse_json_lines = enabled;
        self
    }

    /// Set max JSON lines to retain.
    #[must_use]
    pub const fn with_max_json_lines(mut self, max: usize) -> Self {
        self.max_json_lines = max;
        self
    }
}

/// Captured output from a connector process.
#[derive(Debug, Clone)]
pub struct OutputCapture {
    /// Ring buffer for stdout.
    stdout: RingBuffer,
    /// Ring buffer for stderr.
    stderr: RingBuffer,
    /// Parsed JSON lines from stdout (most recent first).
    json_lines: VecDeque<serde_json::Value>,
    /// Configuration.
    config: OutputCaptureConfig,
    /// Partial stdout line accumulator for JSON parsing.
    stdout_line_buf: Vec<u8>,
}

impl OutputCapture {
    /// Create a new output capture with the given config.
    #[must_use]
    pub fn new(config: OutputCaptureConfig) -> Self {
        let stdout = RingBuffer::new(config.stdout_capacity);
        let stderr = RingBuffer::new(config.stderr_capacity);
        Self {
            stdout,
            stderr,
            json_lines: VecDeque::new(),
            config,
            stdout_line_buf: Vec::new(),
        }
    }

    /// Create with default config.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(OutputCaptureConfig::default())
    }

    /// Write stdout bytes.
    pub fn write_stdout(&mut self, bytes: &[u8]) {
        self.stdout.write(bytes);

        if self.config.parse_json_lines {
            self.parse_lines(bytes);
        }
    }

    /// Write stderr bytes.
    pub fn write_stderr(&mut self, bytes: &[u8]) {
        self.stderr.write(bytes);
    }

    /// Parse newline-delimited JSON from bytes.
    fn parse_lines(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                // Try to parse accumulated line as JSON.
                if let Ok(line_str) = std::str::from_utf8(&self.stdout_line_buf) {
                    let trimmed = line_str.trim();
                    if !trimmed.is_empty() && let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
                        self.json_lines.push_front(value);
                        if self.json_lines.len() > self.config.max_json_lines {
                            self.json_lines.pop_back();
                        }
                    }
                }
                self.stdout_line_buf.clear();
            } else {
                self.stdout_line_buf.push(b);
            }
        }
    }

    /// Get the last N bytes of stdout and stderr.
    #[must_use]
    pub fn tail(&self, n: usize) -> (String, String) {
        (
            String::from_utf8_lossy(&self.stdout.last_n(n)).into_owned(),
            String::from_utf8_lossy(&self.stderr.last_n(n)).into_owned(),
        )
    }

    /// Get all stdout as a string (lossy).
    #[must_use]
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.stdout.contents()).into_owned()
    }

    /// Get all stderr as a string (lossy).
    #[must_use]
    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr.contents()).into_owned()
    }

    /// Get parsed JSON lines (most recent first).
    #[must_use]
    pub const fn json_lines(&self) -> &VecDeque<serde_json::Value> {
        &self.json_lines
    }

    /// Get the most recent JSON line.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // VecDeque::front not const
    pub fn latest_json(&self) -> Option<&serde_json::Value> {
        self.json_lines.front()
    }

    /// Number of parsed JSON lines.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // VecDeque::len not const
    pub fn json_line_count(&self) -> usize {
        self.json_lines.len()
    }

    /// Stdout buffer stats.
    #[must_use]
    pub fn stdout_stats(&self) -> BufferStats {
        BufferStats {
            len: self.stdout.len(),
            capacity: self.stdout.capacity(),
            total_written: self.stdout.total_written(),
            has_overflow: self.stdout.has_overflow(),
        }
    }

    /// Stderr buffer stats.
    #[must_use]
    pub fn stderr_stats(&self) -> BufferStats {
        BufferStats {
            len: self.stderr.len(),
            capacity: self.stderr.capacity(),
            total_written: self.stderr.total_written(),
            has_overflow: self.stderr.has_overflow(),
        }
    }

    /// Clear all captured output.
    pub fn clear(&mut self) {
        self.stdout.clear();
        self.stderr.clear();
        self.json_lines.clear();
        self.stdout_line_buf.clear();
    }
}

/// Statistics for a single output buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferStats {
    /// Current bytes in buffer.
    pub len: usize,
    /// Buffer capacity.
    pub capacity: usize,
    /// Total bytes ever written.
    pub total_written: u64,
    /// Whether data has been lost.
    pub has_overflow: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector installer types
// ─────────────────────────────────────────────────────────────────────────────

/// Status of a connector installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallStatus {
    /// Not installed.
    NotInstalled,
    /// Currently being installed.
    Installing,
    /// Installed and ready.
    Installed,
    /// Installation failed.
    Failed {
        /// Error description.
        error: String,
    },
    /// Being updated to a new version.
    Updating {
        /// Version being updated from.
        from_version: String,
        /// Version being updated to.
        to_version: String,
    },
    /// Being uninstalled.
    Uninstalling,
}

impl InstallStatus {
    /// Whether the connector is installed and ready.
    #[must_use]
    pub const fn is_installed(&self) -> bool {
        matches!(self, Self::Installed)
    }

    /// Whether an operation is in progress.
    #[must_use]
    pub const fn is_in_progress(&self) -> bool {
        matches!(
            self,
            Self::Installing | Self::Updating { .. } | Self::Uninstalling
        )
    }

    /// Human-readable label.
    #[must_use]
    pub const fn label(&self) -> &str {
        match self {
            Self::NotInstalled => "not_installed",
            Self::Installing => "installing",
            Self::Installed => "installed",
            Self::Failed { .. } => "failed",
            Self::Updating { .. } => "updating",
            Self::Uninstalling => "uninstalling",
        }
    }
}

impl std::fmt::Display for InstallStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(f, "not installed"),
            Self::Installing => write!(f, "installing"),
            Self::Installed => write!(f, "installed"),
            Self::Failed { error } => write!(f, "failed: {error}"),
            Self::Updating {
                from_version,
                to_version,
            } => write!(f, "updating {from_version} → {to_version}"),
            Self::Uninstalling => write!(f, "uninstalling"),
        }
    }
}

/// Options for installing a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct InstallOptions {
    /// Whether to perform a dry run (check without installing).
    pub dry_run: bool,
    /// Whether to mirror the installed connector to the mesh.
    pub mirror_to_mesh: bool,
    /// Whether to skip signature verification (dev mode only).
    pub skip_signature: bool,
    /// Override for binary platform target.
    pub target_override: Option<String>,
    /// Force reinstall even if already installed.
    pub force: bool,
}

impl Default for InstallOptions {
    #[allow(clippy::missing_const_for_fn)]
    fn default() -> Self {
        Self {
            dry_run: false,
            mirror_to_mesh: false,
            skip_signature: false,
            target_override: None,
            force: false,
        }
    }
}

impl InstallOptions {
    /// Create default install options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable dry run.
    #[must_use]
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Enable mesh mirroring.
    #[must_use]
    pub const fn mirror_to_mesh(mut self) -> Self {
        self.mirror_to_mesh = true;
        self
    }

    /// Enable force reinstall.
    #[must_use]
    pub const fn force(mut self) -> Self {
        self.force = true;
        self
    }
}

/// Record of an installed connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledConnector {
    /// Connector identifier.
    pub connector_id: String,
    /// Installed version.
    pub version: String,
    /// Installation path.
    pub install_path: String,
    /// Binary hash (for verification).
    pub binary_hash: String,
    /// Manifest hash.
    pub manifest_hash: String,
    /// When the connector was installed (unix timestamp ms).
    pub installed_at_ms: u64,
    /// Who/what initiated the installation.
    pub installed_by: String,
    /// Whether signature was verified.
    pub signature_verified: bool,
    /// Supply chain verification decision.
    pub supply_chain_status: VerificationStatus,
}

/// Supply chain verification status for an installed connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Verified — all checks passed.
    Verified,
    /// Unverified — no attestation available but allowed by policy.
    Unverified,
    /// Skipped — verification was explicitly skipped (dev mode).
    Skipped,
    /// Failed — verification failed.
    Failed {
        /// Reason for failure.
        reason: String,
    },
}

impl VerificationStatus {
    /// Whether this is a passing status.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Verified | Self::Unverified | Self::Skipped)
    }
}

/// Result of an install operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallResult {
    /// Whether the install was a dry run.
    pub dry_run: bool,
    /// The installed connector (None for dry runs).
    pub connector: Option<InstalledConnector>,
    /// Steps performed during installation.
    pub steps: Vec<InstallStep>,
    /// Whether the install succeeded.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

impl InstallResult {
    /// Create a successful result.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn success(connector: InstalledConnector) -> Self {
        Self {
            dry_run: false,
            connector: Some(connector),
            steps: Vec::new(),
            success: true,
            error: None,
        }
    }

    /// Create a dry-run result.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn dry_run_ok(steps: Vec<InstallStep>) -> Self {
        Self {
            dry_run: true,
            connector: None,
            steps,
            success: true,
            error: None,
        }
    }

    /// Create a failed result.
    #[must_use]
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            dry_run: false,
            connector: None,
            steps: Vec::new(),
            success: false,
            error: Some(error.into()),
        }
    }

    /// Attach steps to the result.
    #[must_use]
    pub fn with_steps(mut self, steps: Vec<InstallStep>) -> Self {
        self.steps = steps;
        self
    }
}

/// A single step in the install process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallStep {
    /// Step name.
    pub name: String,
    /// Whether the step passed.
    pub passed: bool,
    /// Duration in milliseconds.
    pub elapsed_ms: f64,
    /// Detail message.
    pub detail: String,
}

impl InstallStep {
    /// Create a passed step.
    #[must_use]
    pub fn passed(name: impl Into<String>, detail: impl Into<String>, elapsed_ms: f64) -> Self {
        Self {
            name: name.into(),
            passed: true,
            elapsed_ms,
            detail: detail.into(),
        }
    }

    /// Create a failed step.
    #[must_use]
    pub fn failed(name: impl Into<String>, detail: impl Into<String>, elapsed_ms: f64) -> Self {
        Self {
            name: name.into(),
            passed: false,
            elapsed_ms,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ────────── RingBuffer ──────────

    #[test]
    fn ring_buffer_empty() {
        let buf = RingBuffer::new(10);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), 10);
        assert_eq!(buf.total_written(), 0);
        assert!(!buf.has_overflow());
    }

    #[test]
    fn ring_buffer_write_within_capacity() {
        let mut buf = RingBuffer::new(10);
        buf.write(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.contents(), b"hello");
        assert!(!buf.has_overflow());
    }

    #[test]
    fn ring_buffer_write_exact_capacity() {
        let mut buf = RingBuffer::new(5);
        buf.write(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.contents(), b"hello");
    }

    #[test]
    fn ring_buffer_overflow() {
        let mut buf = RingBuffer::new(5);
        buf.write(b"hello world");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.contents(), b"world");
        assert!(buf.has_overflow());
        assert_eq!(buf.total_written(), 11);
    }

    #[test]
    fn ring_buffer_incremental_overflow() {
        let mut buf = RingBuffer::new(5);
        buf.write(b"hel");
        buf.write(b"lo!");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.contents(), b"ello!");
        assert!(buf.has_overflow());
    }

    #[test]
    fn ring_buffer_last_n() {
        let mut buf = RingBuffer::new(10);
        buf.write(b"hello world");
        assert_eq!(buf.last_n(5), b"world");
        assert_eq!(buf.last_n(3), b"rld");
    }

    #[test]
    fn ring_buffer_last_n_more_than_available() {
        let mut buf = RingBuffer::new(10);
        buf.write(b"hi");
        assert_eq!(buf.last_n(100), b"hi");
    }

    #[test]
    fn ring_buffer_clear() {
        let mut buf = RingBuffer::new(10);
        buf.write(b"hello");
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.total_written(), 5); // total_written preserved
    }

    #[test]
    fn ring_buffer_multiple_writes() {
        let mut buf = RingBuffer::new(10);
        buf.write(b"aaa");
        buf.write(b"bbb");
        buf.write(b"ccc");
        assert_eq!(buf.len(), 9);
        assert_eq!(buf.contents(), b"aaabbbccc");
    }

    #[test]
    fn ring_buffer_zero_capacity() {
        let mut buf = RingBuffer::new(0);
        buf.write(b"hello");
        assert!(buf.is_empty());
        assert_eq!(buf.total_written(), 5);
    }

    #[test]
    fn ring_buffer_single_byte_capacity() {
        let mut buf = RingBuffer::new(1);
        buf.write(b"abc");
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.contents(), b"c");
    }

    #[test]
    fn ring_buffer_last_n_zero() {
        let mut buf = RingBuffer::new(10);
        buf.write(b"hello");
        assert!(buf.last_n(0).is_empty());
    }

    // ────────── OutputCaptureConfig ──────────

    #[test]
    fn config_defaults() {
        let c = OutputCaptureConfig::default();
        assert_eq!(c.stdout_capacity, 64 * 1024);
        assert_eq!(c.stderr_capacity, 64 * 1024);
        assert!(c.parse_json_lines);
        assert_eq!(c.max_json_lines, 100);
    }

    #[test]
    fn config_builder() {
        let c = OutputCaptureConfig::new()
            .with_stdout_capacity(1024)
            .with_stderr_capacity(2048)
            .with_json_parsing(false)
            .with_max_json_lines(50);
        assert_eq!(c.stdout_capacity, 1024);
        assert_eq!(c.stderr_capacity, 2048);
        assert!(!c.parse_json_lines);
        assert_eq!(c.max_json_lines, 50);
    }

    // ────────── OutputCapture ──────────

    #[test]
    fn capture_stdout() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"hello stdout\n");
        assert_eq!(cap.stdout_string(), "hello stdout\n");
    }

    #[test]
    fn capture_stderr() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stderr(b"error msg\n");
        assert_eq!(cap.stderr_string(), "error msg\n");
    }

    #[test]
    fn capture_tail() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"stdout data");
        cap.write_stderr(b"stderr data");
        let (stdout, stderr) = cap.tail(5);
        assert_eq!(stdout, " data");
        assert_eq!(stderr, " data");
    }

    #[test]
    fn capture_json_parsing() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"{\"level\":\"info\",\"msg\":\"hello\"}\n");
        assert_eq!(cap.json_line_count(), 1);
        let line = cap.latest_json().unwrap();
        assert_eq!(line["msg"], "hello");
    }

    #[test]
    fn capture_json_non_json_ignored() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"not json\n");
        assert_eq!(cap.json_line_count(), 0);
    }

    #[test]
    fn capture_json_multiple_lines() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n");
        assert_eq!(cap.json_line_count(), 3);
        // Most recent first.
        assert_eq!(cap.latest_json().unwrap()["c"], 3);
    }

    #[test]
    fn capture_json_max_lines() {
        let config = OutputCaptureConfig::new().with_max_json_lines(2);
        let mut cap = OutputCapture::new(config);
        cap.write_stdout(b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n");
        assert_eq!(cap.json_line_count(), 2);
        // Oldest evicted.
        assert_eq!(cap.latest_json().unwrap()["c"], 3);
    }

    #[test]
    fn capture_json_partial_line() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"{\"a\":");
        assert_eq!(cap.json_line_count(), 0);
        cap.write_stdout(b"1}\n");
        assert_eq!(cap.json_line_count(), 1);
    }

    #[test]
    fn capture_json_disabled() {
        let config = OutputCaptureConfig::new().with_json_parsing(false);
        let mut cap = OutputCapture::new(config);
        cap.write_stdout(b"{\"a\":1}\n");
        assert_eq!(cap.json_line_count(), 0);
    }

    #[test]
    fn capture_empty_lines_ignored() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"\n\n\n");
        assert_eq!(cap.json_line_count(), 0);
    }

    #[test]
    fn capture_stats() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"hello");
        cap.write_stderr(b"world!");
        let stdout_stats = cap.stdout_stats();
        let stderr_stats = cap.stderr_stats();
        assert_eq!(stdout_stats.len, 5);
        assert_eq!(stderr_stats.len, 6);
        assert_eq!(stdout_stats.total_written, 5);
        assert_eq!(stderr_stats.total_written, 6);
    }

    #[test]
    fn capture_clear() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"{\"a\":1}\n");
        cap.write_stderr(b"error\n");
        cap.clear();
        assert!(cap.stdout_string().is_empty());
        assert!(cap.stderr_string().is_empty());
        assert_eq!(cap.json_line_count(), 0);
    }

    #[test]
    fn capture_mixed_json_and_text() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"Starting...\n{\"status\":\"ready\"}\nDone.\n");
        assert_eq!(cap.json_line_count(), 1);
        assert_eq!(cap.latest_json().unwrap()["status"], "ready");
    }

    // ────────── InstallStatus ──────────

    #[test]
    fn install_status_not_installed() {
        let s = InstallStatus::NotInstalled;
        assert!(!s.is_installed());
        assert!(!s.is_in_progress());
        assert_eq!(s.label(), "not_installed");
        assert_eq!(s.to_string(), "not installed");
    }

    #[test]
    fn install_status_installing() {
        let s = InstallStatus::Installing;
        assert!(!s.is_installed());
        assert!(s.is_in_progress());
        assert_eq!(s.label(), "installing");
    }

    #[test]
    fn install_status_installed() {
        let s = InstallStatus::Installed;
        assert!(s.is_installed());
        assert!(!s.is_in_progress());
        assert_eq!(s.label(), "installed");
    }

    #[test]
    fn install_status_failed() {
        let s = InstallStatus::Failed {
            error: "bad hash".into(),
        };
        assert!(!s.is_installed());
        assert!(!s.is_in_progress());
        assert_eq!(s.label(), "failed");
        assert!(s.to_string().contains("bad hash"));
    }

    #[test]
    fn install_status_updating() {
        let s = InstallStatus::Updating {
            from_version: "1.0.0".into(),
            to_version: "2.0.0".into(),
        };
        assert!(!s.is_installed());
        assert!(s.is_in_progress());
        assert_eq!(s.label(), "updating");
        let display = s.to_string();
        assert!(display.contains("1.0.0"));
        assert!(display.contains("2.0.0"));
    }

    #[test]
    fn install_status_uninstalling() {
        let s = InstallStatus::Uninstalling;
        assert!(!s.is_installed());
        assert!(s.is_in_progress());
    }

    #[test]
    fn install_status_serde_roundtrip() {
        let statuses = vec![
            InstallStatus::NotInstalled,
            InstallStatus::Installing,
            InstallStatus::Installed,
            InstallStatus::Failed {
                error: "err".into(),
            },
            InstallStatus::Updating {
                from_version: "1.0".into(),
                to_version: "2.0".into(),
            },
            InstallStatus::Uninstalling,
        ];
        for s in statuses {
            let json = serde_json::to_string(&s).unwrap();
            let restored: InstallStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, s);
        }
    }

    // ────────── InstallOptions ──────────

    #[test]
    fn install_options_defaults() {
        let o = InstallOptions::default();
        assert!(!o.dry_run);
        assert!(!o.mirror_to_mesh);
        assert!(!o.skip_signature);
        assert!(o.target_override.is_none());
        assert!(!o.force);
    }

    #[test]
    fn install_options_builder() {
        let o = InstallOptions::new().dry_run().mirror_to_mesh().force();
        assert!(o.dry_run);
        assert!(o.mirror_to_mesh);
        assert!(o.force);
    }

    #[test]
    fn install_options_serde_roundtrip() {
        let o = InstallOptions::new().dry_run();
        let json = serde_json::to_string(&o).unwrap();
        let restored: InstallOptions = serde_json::from_str(&json).unwrap();
        assert!(restored.dry_run);
    }

    // ────────── VerificationStatus ──────────

    #[test]
    fn verification_verified_is_ok() {
        assert!(VerificationStatus::Verified.is_ok());
    }

    #[test]
    fn verification_unverified_is_ok() {
        assert!(VerificationStatus::Unverified.is_ok());
    }

    #[test]
    fn verification_skipped_is_ok() {
        assert!(VerificationStatus::Skipped.is_ok());
    }

    #[test]
    fn verification_failed_not_ok() {
        let s = VerificationStatus::Failed {
            reason: "bad".into(),
        };
        assert!(!s.is_ok());
    }

    #[test]
    fn verification_serde_roundtrip() {
        let statuses = vec![
            VerificationStatus::Verified,
            VerificationStatus::Unverified,
            VerificationStatus::Skipped,
            VerificationStatus::Failed {
                reason: "err".into(),
            },
        ];
        for s in statuses {
            let json = serde_json::to_string(&s).unwrap();
            let restored: VerificationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, s);
        }
    }

    // ────────── InstallResult ──────────

    #[test]
    fn install_result_success() {
        let connector = InstalledConnector {
            connector_id: "fcp.discord".into(),
            version: "1.0.0".into(),
            install_path: "/opt/fcp/connectors/discord".into(),
            binary_hash: "abc123".into(),
            manifest_hash: "def456".into(),
            installed_at_ms: 1_000_000,
            installed_by: "operator".into(),
            signature_verified: true,
            supply_chain_status: VerificationStatus::Verified,
        };
        let result = InstallResult::success(connector);
        assert!(result.success);
        assert!(!result.dry_run);
        assert!(result.connector.is_some());
    }

    #[test]
    fn install_result_dry_run() {
        let steps = vec![
            InstallStep::passed("fetch", "fetched manifest", 10.0),
            InstallStep::passed("verify", "signature valid", 5.0),
        ];
        let result = InstallResult::dry_run_ok(steps);
        assert!(result.success);
        assert!(result.dry_run);
        assert!(result.connector.is_none());
        assert_eq!(result.steps.len(), 2);
    }

    #[test]
    fn install_result_failed() {
        let result = InstallResult::failed("network error");
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("network error"));
    }

    #[test]
    fn install_result_with_steps() {
        let result = InstallResult::failed("err").with_steps(vec![
            InstallStep::passed("fetch", "ok", 1.0),
            InstallStep::failed("verify", "hash mismatch", 2.0),
        ]);
        assert_eq!(result.steps.len(), 2);
        assert!(result.steps[0].passed);
        assert!(!result.steps[1].passed);
    }

    #[test]
    fn install_result_serde_roundtrip() {
        let result = InstallResult::failed("test error");
        let json = serde_json::to_string(&result).unwrap();
        let restored: InstallResult = serde_json::from_str(&json).unwrap();
        assert!(!restored.success);
        assert_eq!(restored.error.as_deref(), Some("test error"));
    }

    // ────────── InstallStep ──────────

    #[test]
    fn install_step_passed() {
        let s = InstallStep::passed("fetch", "ok", 10.5);
        assert!(s.passed);
        assert_eq!(s.name, "fetch");
        assert!((s.elapsed_ms - 10.5).abs() < f64::EPSILON);
    }

    #[test]
    fn install_step_failed() {
        let s = InstallStep::failed("verify", "hash mismatch", 5.0);
        assert!(!s.passed);
        assert_eq!(s.detail, "hash mismatch");
    }

    #[test]
    fn install_step_serde_roundtrip() {
        let s = InstallStep::passed("fetch", "ok", 10.0);
        let json = serde_json::to_string(&s).unwrap();
        let restored: InstallStep = serde_json::from_str(&json).unwrap();
        assert!(restored.passed);
        assert_eq!(restored.name, "fetch");
    }

    // ────────── InstalledConnector ──────────

    #[test]
    fn installed_connector_serde_roundtrip() {
        let c = InstalledConnector {
            connector_id: "fcp.slack".into(),
            version: "2.1.0".into(),
            install_path: "/opt/fcp/connectors/slack".into(),
            binary_hash: "aaa".into(),
            manifest_hash: "bbb".into(),
            installed_at_ms: 999,
            installed_by: "agent".into(),
            signature_verified: false,
            supply_chain_status: VerificationStatus::Unverified,
        };
        let json = serde_json::to_string(&c).unwrap();
        let restored: InstalledConnector = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.connector_id, "fcp.slack");
        assert_eq!(restored.version, "2.1.0");
        assert!(!restored.signature_verified);
    }

    // ────────── BufferStats ──────────

    #[test]
    fn buffer_stats_serde_roundtrip() {
        let s = BufferStats {
            len: 100,
            capacity: 1024,
            total_written: 5000,
            has_overflow: true,
        };
        let json = serde_json::to_string(&s).unwrap();
        let restored: BufferStats = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len, 100);
        assert!(restored.has_overflow);
    }

    // ────────── Edge cases ──────────

    #[test]
    fn ring_buffer_write_empty() {
        let mut buf = RingBuffer::new(10);
        buf.write(b"");
        assert!(buf.is_empty());
        assert_eq!(buf.total_written(), 0);
    }

    #[test]
    fn capture_json_whitespace_lines() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"   \n  \t  \n");
        assert_eq!(cap.json_line_count(), 0);
    }

    #[test]
    fn capture_json_large_batch() {
        let config = OutputCaptureConfig::new().with_max_json_lines(5);
        let mut cap = OutputCapture::new(config);
        for i in 0..20 {
            cap.write_stdout(format!("{{\"i\":{i}}}\n").as_bytes());
        }
        assert_eq!(cap.json_line_count(), 5);
        // Most recent is i=19.
        assert_eq!(cap.latest_json().unwrap()["i"], 19);
    }

    #[test]
    fn ring_buffer_exact_double_capacity() {
        let mut buf = RingBuffer::new(5);
        buf.write(b"1234567890");
        assert_eq!(buf.contents(), b"67890");
    }

    #[test]
    fn capture_interleaved_stdout_stderr() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"out1\n");
        cap.write_stderr(b"err1\n");
        cap.write_stdout(b"out2\n");
        cap.write_stderr(b"err2\n");
        assert!(cap.stdout_string().contains("out1"));
        assert!(cap.stdout_string().contains("out2"));
        assert!(cap.stderr_string().contains("err1"));
        assert!(cap.stderr_string().contains("err2"));
    }

    #[test]
    fn capture_latest_json_empty() {
        let cap = OutputCapture::with_defaults();
        assert!(cap.latest_json().is_none());
    }

    #[test]
    fn capture_json_lines_ref() {
        let mut cap = OutputCapture::with_defaults();
        cap.write_stdout(b"{\"x\":1}\n");
        let lines = cap.json_lines();
        assert_eq!(lines.len(), 1);
    }
}
