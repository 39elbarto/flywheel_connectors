//! Operation replay from audit history with optional input overrides.
//!
//! Stores full operation inputs separately from the audit log and allows
//! replaying them with field-level modifications.  Inputs are persisted as
//! base64-encoded JSON files with a configurable TTL (default 7 days).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{env, fs, io::Write};

use anyhow::{Context, Result, bail};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

// ── Constants ───────────────────────────────────────────────────────────────

/// Default time-to-live for stored inputs: 7 days.
const DEFAULT_TTL_DAYS: i64 = 7;

/// Subdirectory within the state root that holds replay inputs.
const REPLAY_DIR_NAME: &str = "replay";

// ── Error types ─────────────────────────────────────────────────────────────

/// Errors specific to replay operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplayError {
    /// The referenced history entry was not found.
    EntryNotFound { entry_id: String },
    /// The stored input has expired and been (or will be) cleaned up.
    InputExpired {
        entry_id: String,
        expired_at: String,
    },
    /// No stored input exists for the given entry.
    InputNotStored { entry_id: String },
    /// An override string could not be parsed.
    InvalidOverride { raw: String, reason: String },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntryNotFound { entry_id } => {
                write!(f, "history entry `{entry_id}` not found")
            }
            Self::InputExpired {
                entry_id,
                expired_at,
            } => {
                write!(f, "stored input for `{entry_id}` expired at {expired_at}")
            }
            Self::InputNotStored { entry_id } => {
                write!(f, "no stored input for entry `{entry_id}`")
            }
            Self::InvalidOverride { raw, reason } => {
                write!(f, "invalid override `{raw}`: {reason}")
            }
        }
    }
}

impl std::error::Error for ReplayError {}

// ── History types (lightweight, self-contained) ─────────────────────────────

/// Status of a previously-executed operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpStatus {
    Success,
    Failure,
    Denied,
    Timeout,
}

impl OpStatus {
    /// Return the canonical string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for OpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An entry in the operation history / audit log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unique identifier for this history entry.
    pub entry_id: String,
    /// Connector that was invoked.
    pub connector_id: String,
    /// Operation within the connector.
    pub operation_id: String,
    /// SHA-256 hex digest of the serialized input.
    pub input_hash: String,
    /// Short human-readable summary of the input.
    pub input_summary: String,
    /// Outcome status.
    pub status: OpStatus,
    /// ISO-8601 timestamp of the invocation.
    pub invoked_at: String,
}

/// Filter criteria for querying history.
#[derive(Clone, Debug, Default)]
pub struct HistoryFilter {
    pub connector_id: Option<String>,
    pub operation_id: Option<String>,
    pub status: Option<OpStatus>,
    pub limit: Option<usize>,
}

/// In-memory history store backed by a JSON-lines file.
#[derive(Clone, Debug)]
pub struct HistoryStore {
    entries: Vec<HistoryEntry>,
}

impl HistoryStore {
    /// Create an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append an entry to the store.
    pub fn append(&mut self, entry: HistoryEntry) {
        self.entries.push(entry);
    }

    /// Get an entry by its id.
    #[must_use]
    pub fn get(&self, entry_id: &str) -> Option<&HistoryEntry> {
        self.entries.iter().find(|e| e.entry_id == entry_id)
    }

    /// Query entries matching a filter, newest first.
    #[must_use]
    pub fn query(&self, filter: &HistoryFilter) -> Vec<&HistoryEntry> {
        let mut matches: Vec<&HistoryEntry> = self
            .entries
            .iter()
            .filter(|e| {
                filter
                    .connector_id
                    .as_ref()
                    .is_none_or(|cid| cid == &e.connector_id)
            })
            .filter(|e| {
                filter
                    .operation_id
                    .as_ref()
                    .is_none_or(|oid| oid == &e.operation_id)
            })
            .filter(|e| filter.status.is_none_or(|s| s == e.status))
            .collect();
        // Reverse to get newest first (entries are appended chronologically).
        matches.reverse();
        if let Some(limit) = filter.limit {
            matches.truncate(limit);
        }
        matches
    }

    /// Total number of entries.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

/// Compute a hex-encoded SHA-256-style content hash (simplified: uses serde
/// serialization determinism).  Uses a basic FNV-like hash for portability
/// without pulling in `sha2`.
#[must_use]
pub fn content_hash(input: &Value) -> String {
    let bytes = serde_json::to_vec(input).unwrap_or_default();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in &bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Produce a short summary string for an input value.
#[must_use]
pub fn summarize_input(input: &Value) -> String {
    match input {
        Value::Object(map) => {
            let keys: Vec<&str> = map.keys().map(String::as_str).take(4).collect();
            if keys.len() < map.len() {
                format!("{{{}, ...}} ({} keys)", keys.join(", "), map.len())
            } else {
                format!("{{{}}}", keys.join(", "))
            }
        }
        Value::Array(arr) => format!("[...] ({} items)", arr.len()),
        Value::String(s) => {
            if s.len() > 40 {
                format!("\"{}...\"", &s[..37])
            } else {
                format!("\"{s}\"")
            }
        }
        other => other.to_string(),
    }
}

// ── Stored input ────────────────────────────────────────────────────────────

/// A full operation input persisted for later replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredInput {
    /// History entry id this input corresponds to.
    pub entry_id: String,
    /// Connector that was invoked.
    pub connector_id: String,
    /// Operation within the connector.
    pub operation_id: String,
    /// The full input payload (base64-encoded JSON when on disk).
    pub input: Value,
    /// When the input was stored (ISO-8601).
    pub stored_at: String,
    /// When the input expires (ISO-8601).
    pub expires_at: String,
}

/// On-disk representation with base64-encoded input.
#[derive(Serialize, Deserialize)]
struct StoredInputDisk {
    entry_id: String,
    connector_id: String,
    operation_id: String,
    /// Base64-encoded JSON of the input value.
    input_b64: String,
    stored_at: String,
    expires_at: String,
}

impl StoredInputDisk {
    fn from_stored(stored: &StoredInput) -> Result<Self> {
        let json_bytes = serde_json::to_vec(&stored.input)
            .context("failed to serialize input for base64 encoding")?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&json_bytes);
        Ok(Self {
            entry_id: stored.entry_id.clone(),
            connector_id: stored.connector_id.clone(),
            operation_id: stored.operation_id.clone(),
            input_b64: b64,
            stored_at: stored.stored_at.clone(),
            expires_at: stored.expires_at.clone(),
        })
    }

    fn into_stored(self) -> Result<StoredInput> {
        let json_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.input_b64)
            .context("failed to decode base64 input")?;
        let input: Value =
            serde_json::from_slice(&json_bytes).context("failed to parse decoded input JSON")?;
        Ok(StoredInput {
            entry_id: self.entry_id,
            connector_id: self.connector_id,
            operation_id: self.operation_id,
            input,
            stored_at: self.stored_at,
            expires_at: self.expires_at,
        })
    }
}

// ── Replay request / plan ───────────────────────────────────────────────────

/// A request to replay a previous operation, optionally with overrides.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayRequest {
    /// History entry id to replay.
    pub entry_id: String,
    /// Field overrides to apply (dot-path -> value).
    pub overrides: HashMap<String, Value>,
    /// If true, compute the plan but do not execute.
    pub dry_run: bool,
}

impl ReplayRequest {
    /// Create a simple replay request with no overrides.
    #[must_use]
    pub fn simple(entry_id: impl Into<String>) -> Self {
        Self {
            entry_id: entry_id.into(),
            overrides: HashMap::new(),
            dry_run: false,
        }
    }

    /// Add an override to the request.
    #[must_use]
    pub fn with_override(mut self, key: impl Into<String>, value: Value) -> Self {
        self.overrides.insert(key.into(), value);
        self
    }

    /// Mark as dry-run.
    #[must_use]
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }
}

/// A computed replay plan ready for execution (or preview in dry-run mode).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayPlan {
    /// The original stored input.
    pub original: StoredInput,
    /// The effective input after overrides are applied.
    pub effective_input: Value,
    /// List of override paths that were applied.
    pub overrides_applied: Vec<String>,
    /// Target connector id.
    pub connector_id: String,
    /// Target operation id.
    pub operation_id: String,
    /// Whether this is a dry-run plan.
    pub dry_run: bool,
}

// ── Override parsing ────────────────────────────────────────────────────────

/// Represents a single field override parsed from `key=value` syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputOverride {
    /// Dot-separated path (e.g. `"config.timeout"`).
    pub path: String,
    /// The parsed value.
    pub value: Value,
}

/// Parse an override string in `key=value` or `key.nested.path=value` format.
///
/// Values that parse as valid JSON are used as-is; otherwise they are treated
/// as plain strings.
///
/// # Errors
///
/// Returns `ReplayError::InvalidOverride` if the string has no `=` separator
/// or the key is empty.
pub fn parse_override(s: &str) -> std::result::Result<(String, Value), ReplayError> {
    let Some((key, raw_value)) = s.split_once('=') else {
        return Err(ReplayError::InvalidOverride {
            raw: s.to_owned(),
            reason: "missing `=` separator".to_owned(),
        });
    };

    let key = key.trim();
    if key.is_empty() {
        return Err(ReplayError::InvalidOverride {
            raw: s.to_owned(),
            reason: "key is empty".to_owned(),
        });
    }

    let raw_value = raw_value.trim();
    // Try parsing as JSON first; fall back to plain string.
    let value =
        serde_json::from_str(raw_value).unwrap_or_else(|_| Value::String(raw_value.to_owned()));

    Ok((key.to_owned(), value))
}

/// Apply a set of overrides (dot-path, value) to a JSON value via deep merge.
///
/// Each path segment is separated by `.` and navigates (or creates) nested
/// objects.  The final segment sets the value.
///
/// # Errors
///
/// Returns an error if a path segment tries to traverse a non-object value.
pub fn apply_overrides(input: &Value, overrides: &[(String, Value)]) -> Result<Value> {
    let mut result = input.clone();

    for (path, value) in overrides {
        set_nested_value(&mut result, path, value.clone())
            .with_context(|| format!("failed to apply override at path `{path}`"))?;
    }

    Ok(result)
}

/// Set a value at a dot-separated path within a JSON value.
fn set_nested_value(root: &mut Value, path: &str, value: Value) -> Result<()> {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() {
        bail!("empty path");
    }

    let mut current = root;
    for (i, segment) in segments.iter().enumerate() {
        if i == segments.len() - 1 {
            // Final segment: set the value.
            match current {
                Value::Object(map) => {
                    map.insert((*segment).to_owned(), value);
                    return Ok(());
                }
                Value::Null => {
                    // Auto-create object.
                    *current = serde_json::json!({});
                    if let Value::Object(map) = current {
                        map.insert((*segment).to_owned(), value);
                    }
                    return Ok(());
                }
                other => {
                    bail!(
                        "cannot set key `{segment}` on non-object value (found {})",
                        value_type_name(other)
                    );
                }
            }
        }

        // Intermediate segment: navigate or create.
        match current {
            Value::Object(map) => {
                current = map
                    .entry((*segment).to_owned())
                    .or_insert_with(|| serde_json::json!({}));
            }
            Value::Null => {
                *current = serde_json::json!({});
                if let Value::Object(map) = current {
                    current = map
                        .entry((*segment).to_owned())
                        .or_insert_with(|| serde_json::json!({}));
                }
            }
            other => {
                bail!(
                    "cannot traverse key `{segment}` in non-object value (found {})",
                    value_type_name(other)
                );
            }
        }
    }

    Ok(())
}

const fn value_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ── Replay store ────────────────────────────────────────────────────────────

/// File-system-backed store for replay inputs.
#[derive(Clone, Debug)]
pub struct ReplayStore {
    root_dir: PathBuf,
    ttl_days: i64,
}

impl ReplayStore {
    /// Discover the default replay store location.
    ///
    /// # Errors
    ///
    /// Returns an error if the state directory cannot be determined.
    pub fn discover() -> Result<Self> {
        Ok(Self {
            root_dir: default_replay_root()?,
            ttl_days: DEFAULT_TTL_DAYS,
        })
    }

    /// Create a store rooted at a specific path (used in tests).
    #[cfg(test)]
    #[must_use]
    pub const fn at_path(path: PathBuf) -> Self {
        Self {
            root_dir: path,
            ttl_days: DEFAULT_TTL_DAYS,
        }
    }

    /// Create a store with a custom TTL (used in tests).
    #[cfg(test)]
    #[must_use]
    pub const fn with_ttl(mut self, ttl_days: i64) -> Self {
        self.ttl_days = ttl_days;
        self
    }

    /// Store the input for a given history entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn store_input(
        &self,
        entry_id: &str,
        connector_id: &str,
        operation_id: &str,
        input: &Value,
    ) -> Result<()> {
        self.ensure_dir()?;

        let now = Utc::now();
        let expires = now + Duration::days(self.ttl_days);

        let stored = StoredInput {
            entry_id: entry_id.to_owned(),
            connector_id: connector_id.to_owned(),
            operation_id: operation_id.to_owned(),
            input: input.clone(),
            stored_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        };

        let disk = StoredInputDisk::from_stored(&stored)?;
        let json_bytes =
            serde_json::to_vec_pretty(&disk).context("failed to serialize stored input")?;

        let final_path = self.input_path(entry_id);
        let temp_path = final_path.with_extension(format!("tmp.{}", Uuid::new_v4().simple()));

        let file = fs::File::create(&temp_path).with_context(|| {
            format!(
                "failed to create temporary replay file `{}`",
                temp_path.display()
            )
        })?;
        let mut writer = std::io::BufWriter::new(&file);
        writer.write_all(&json_bytes)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        file.sync_all()?;

        fs::rename(&temp_path, &final_path).with_context(|| {
            format!(
                "failed to persist replay input for `{entry_id}` to `{}`",
                final_path.display()
            )
        })?;

        Ok(())
    }

    /// Retrieve a stored input by entry id.
    ///
    /// Returns `None` if the file does not exist.  Returns an expired-input
    /// error if the input exists but has passed its TTL.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O or parse failures.
    pub fn get_stored_input(
        &self,
        entry_id: &str,
    ) -> std::result::Result<Option<StoredInput>, ReplayError> {
        let path = self.input_path(entry_id);
        if !path.exists() {
            return Ok(None);
        }

        let bytes = fs::read(&path).map_err(|_| ReplayError::InputNotStored {
            entry_id: entry_id.to_owned(),
        })?;

        let disk: StoredInputDisk =
            serde_json::from_slice(&bytes).map_err(|_| ReplayError::InputNotStored {
                entry_id: entry_id.to_owned(),
            })?;

        let stored = disk
            .into_stored()
            .map_err(|_| ReplayError::InputNotStored {
                entry_id: entry_id.to_owned(),
            })?;

        // Check TTL.
        if let Ok(expires) = stored.expires_at.parse::<DateTime<Utc>>() {
            if Utc::now() > expires {
                return Err(ReplayError::InputExpired {
                    entry_id: entry_id.to_owned(),
                    expired_at: stored.expires_at,
                });
            }
        }

        Ok(Some(stored))
    }

    /// List all stored entry ids (including potentially expired ones).
    #[must_use]
    pub fn list_entry_ids(&self) -> Vec<String> {
        let dir = self.replay_dir();
        if !dir.exists() {
            return Vec::new();
        }

        fs::read_dir(&dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "json") {
                    path.file_stem().map(|s| s.to_string_lossy().into_owned())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Remove all stored inputs whose TTL has expired.
    ///
    /// Returns the number of entries cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read.
    pub fn cleanup_expired(&self) -> Result<usize> {
        let dir = self.replay_dir();
        if !dir.exists() {
            return Ok(0);
        }

        let now = Utc::now();
        let mut removed = 0usize;

        let entries = fs::read_dir(&dir)
            .with_context(|| format!("failed to read replay directory `{}`", dir.display()))?;

        for entry in entries.filter_map(std::result::Result::ok) {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }

            if let Ok(bytes) = fs::read(&path) {
                if let Ok(disk) = serde_json::from_slice::<StoredInputDisk>(&bytes) {
                    if let Ok(expires) = disk.expires_at.parse::<DateTime<Utc>>() {
                        if now > expires && fs::remove_file(&path).is_ok() {
                            removed += 1;
                        }
                    }
                }
            }
        }

        Ok(removed)
    }

    /// The root directory for this store.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    fn replay_dir(&self) -> PathBuf {
        self.root_dir.join(REPLAY_DIR_NAME)
    }

    fn input_path(&self, entry_id: &str) -> PathBuf {
        self.replay_dir()
            .join(format!("{}.json", entry_id.replace(':', "_")))
    }

    fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(self.replay_dir()).with_context(|| {
            format!(
                "failed to create replay directory `{}`",
                self.replay_dir().display()
            )
        })
    }
}

// ── Plan generation ─────────────────────────────────────────────────────────

/// Build a replay plan for the given request.
///
/// Looks up the stored input, applies overrides, and returns a plan describing
/// what would be executed.
///
/// # Errors
///
/// Returns a `ReplayError` if the entry or stored input cannot be found or has
/// expired, wrapped in `anyhow`.
pub fn plan_replay(
    request: &ReplayRequest,
    store: &ReplayStore,
    history: &HistoryStore,
) -> Result<ReplayPlan> {
    // Verify the history entry exists.
    let _entry = history
        .get(&request.entry_id)
        .ok_or_else(|| ReplayError::EntryNotFound {
            entry_id: request.entry_id.clone(),
        })?;

    // Retrieve the stored input.
    let stored = store
        .get_stored_input(&request.entry_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| ReplayError::InputNotStored {
            entry_id: request.entry_id.clone(),
        })?;

    // Apply overrides.
    let override_pairs: Vec<(String, Value)> = request
        .overrides
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let effective_input = if override_pairs.is_empty() {
        stored.input.clone()
    } else {
        apply_overrides(&stored.input, &override_pairs)?
    };

    let overrides_applied: Vec<String> = request.overrides.keys().cloned().collect();

    Ok(ReplayPlan {
        connector_id: stored.connector_id.clone(),
        operation_id: stored.operation_id.clone(),
        original: stored,
        effective_input,
        overrides_applied,
        dry_run: request.dry_run,
    })
}

/// Find the most recent history entry for a given operation id.
#[must_use]
pub fn find_last_of(operation_id: &str, history: &HistoryStore) -> Option<HistoryEntry> {
    let filter = HistoryFilter {
        operation_id: Some(operation_id.to_owned()),
        limit: Some(1),
        ..HistoryFilter::default()
    };
    history.query(&filter).into_iter().next().cloned()
}

// ── State root ──────────────────────────────────────────────────────────────

fn default_replay_root() -> Result<PathBuf> {
    if let Some(override_dir) = env::var_os("FWC_STATE_DIR") {
        return Ok(PathBuf::from(override_dir));
    }

    #[cfg(test)]
    if let Some(tmpdir) = env::var_os("CARGO_TARGET_TMPDIR") {
        return Ok(PathBuf::from(tmpdir).join(format!("fwc-replay-tests-{}", std::process::id())));
    }

    if let Some(state_home) = env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(state_home).join("fwc"));
    }

    if let Some(home) = env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".local").join("state").join("fwc"));
    }

    env::current_dir()
        .map(|cwd| cwd.join(".fwc-state"))
        .context("failed to derive a default replay state directory")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn temp_store() -> ReplayStore {
        let dir = std::env::temp_dir().join(format!("fwc-replay-test-{}", Uuid::new_v4().simple()));
        ReplayStore::at_path(dir)
    }

    fn sample_input() -> Value {
        json!({
            "title": "Hello World",
            "body": "Some content",
            "labels": ["bug", "p1"],
            "config": {
                "timeout": 30,
                "retry": true
            }
        })
    }

    fn sample_history_entry(entry_id: &str) -> HistoryEntry {
        HistoryEntry {
            entry_id: entry_id.to_owned(),
            connector_id: "github".to_owned(),
            operation_id: "issues.create".to_owned(),
            input_hash: content_hash(&sample_input()),
            input_summary: summarize_input(&sample_input()),
            status: OpStatus::Success,
            invoked_at: Utc::now().to_rfc3339(),
        }
    }

    // ── ReplayStore lifecycle ───────────────────────────────────────────

    #[test]
    fn store_and_retrieve_input() {
        let store = temp_store();
        let input = sample_input();

        store
            .store_input("e001", "github", "issues.create", &input)
            .unwrap();

        let stored = store.get_stored_input("e001").unwrap().unwrap();
        assert_eq!(stored.entry_id, "e001");
        assert_eq!(stored.connector_id, "github");
        assert_eq!(stored.operation_id, "issues.create");
        assert_eq!(stored.input, input);
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = temp_store();
        let result = store.get_stored_input("does-not-exist").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_entry_ids_empty_store() {
        let store = temp_store();
        assert!(store.list_entry_ids().is_empty());
    }

    #[test]
    fn list_entry_ids_returns_stored() {
        let store = temp_store();
        let input = sample_input();
        store
            .store_input("e001", "github", "issues.create", &input)
            .unwrap();
        store
            .store_input("e002", "slack", "chat.post", &input)
            .unwrap();

        let mut ids = store.list_entry_ids();
        ids.sort();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"e001".to_owned()));
        assert!(ids.contains(&"e002".to_owned()));
    }

    #[test]
    fn store_overwrites_existing() {
        let store = temp_store();
        let input1 = json!({"v": 1});
        let input2 = json!({"v": 2});

        store
            .store_input("e001", "github", "issues.create", &input1)
            .unwrap();
        store
            .store_input("e001", "github", "issues.create", &input2)
            .unwrap();

        let stored = store.get_stored_input("e001").unwrap().unwrap();
        assert_eq!(stored.input, input2);
    }

    #[test]
    fn cleanup_expired_removes_old_entries() {
        let store = temp_store().with_ttl(0); // Expire immediately.
        let input = sample_input();

        store
            .store_input("e001", "github", "issues.create", &input)
            .unwrap();

        // Manually backdate the expiry to the past.
        let path = store.input_path("e001");
        let bytes = fs::read(&path).unwrap();
        let mut disk: StoredInputDisk = serde_json::from_slice(&bytes).unwrap();
        disk.expires_at = (Utc::now() - Duration::hours(1)).to_rfc3339();
        fs::write(&path, serde_json::to_vec_pretty(&disk).unwrap()).unwrap();

        let removed = store.cleanup_expired().unwrap();
        assert_eq!(removed, 1);
        assert!(store.list_entry_ids().is_empty());
    }

    #[test]
    fn cleanup_expired_keeps_valid_entries() {
        let store = temp_store();
        let input = sample_input();

        store
            .store_input("e001", "github", "issues.create", &input)
            .unwrap();

        let removed = store.cleanup_expired().unwrap();
        assert_eq!(removed, 0);
        assert_eq!(store.list_entry_ids().len(), 1);
    }

    #[test]
    fn cleanup_expired_on_empty_dir() {
        let store = temp_store();
        let removed = store.cleanup_expired().unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn expired_input_returns_error() {
        let store = temp_store();
        let input = sample_input();

        store
            .store_input("e001", "github", "issues.create", &input)
            .unwrap();

        // Backdate the expiry.
        let path = store.input_path("e001");
        let bytes = fs::read(&path).unwrap();
        let mut disk: StoredInputDisk = serde_json::from_slice(&bytes).unwrap();
        disk.expires_at = (Utc::now() - Duration::hours(1)).to_rfc3339();
        fs::write(&path, serde_json::to_vec_pretty(&disk).unwrap()).unwrap();

        let result = store.get_stored_input("e001");
        assert!(result.is_err());
        match result.unwrap_err() {
            ReplayError::InputExpired { entry_id, .. } => assert_eq!(entry_id, "e001"),
            other => panic!("expected InputExpired, got {other:?}"),
        }
    }

    // ── Override parsing ────────────────────────────────────────────────

    #[test]
    fn parse_override_simple_string() {
        let (key, value) = parse_override("title=New Title").unwrap();
        assert_eq!(key, "title");
        assert_eq!(value, Value::String("New Title".to_owned()));
    }

    #[test]
    fn parse_override_json_number() {
        let (key, value) = parse_override("count=42").unwrap();
        assert_eq!(key, "count");
        assert_eq!(value, json!(42));
    }

    #[test]
    fn parse_override_json_bool() {
        let (key, value) = parse_override("active=true").unwrap();
        assert_eq!(key, "active");
        assert_eq!(value, json!(true));
    }

    #[test]
    fn parse_override_json_array() {
        let (key, value) = parse_override(r#"labels=["bug","p1"]"#).unwrap();
        assert_eq!(key, "labels");
        assert_eq!(value, json!(["bug", "p1"]));
    }

    #[test]
    fn parse_override_json_object() {
        let (key, value) = parse_override(r#"config={"timeout":60}"#).unwrap();
        assert_eq!(key, "config");
        assert_eq!(value, json!({"timeout": 60}));
    }

    #[test]
    fn parse_override_nested_path() {
        let (key, value) = parse_override("config.timeout=30").unwrap();
        assert_eq!(key, "config.timeout");
        assert_eq!(value, json!(30));
    }

    #[test]
    fn parse_override_json_null() {
        let (key, value) = parse_override("field=null").unwrap();
        assert_eq!(key, "field");
        assert_eq!(value, Value::Null);
    }

    #[test]
    fn parse_override_missing_equals() {
        let result = parse_override("no-equals-here");
        assert!(result.is_err());
        match result.unwrap_err() {
            ReplayError::InvalidOverride { raw, reason } => {
                assert_eq!(raw, "no-equals-here");
                assert!(reason.contains("missing"));
            }
            other => panic!("expected InvalidOverride, got {other:?}"),
        }
    }

    #[test]
    fn parse_override_empty_key() {
        let result = parse_override("=value");
        assert!(result.is_err());
        match result.unwrap_err() {
            ReplayError::InvalidOverride { reason, .. } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("expected InvalidOverride, got {other:?}"),
        }
    }

    #[test]
    fn parse_override_empty_value_treated_as_string() {
        let (key, value) = parse_override("key=").unwrap();
        assert_eq!(key, "key");
        assert_eq!(value, Value::String(String::new()));
    }

    #[test]
    fn parse_override_whitespace_trimming() {
        let (key, value) = parse_override("  title  =  hello world  ").unwrap();
        assert_eq!(key, "title");
        assert_eq!(value, Value::String("hello world".to_owned()));
    }

    #[test]
    fn parse_override_value_with_equals_sign() {
        let (key, value) = parse_override("query=a=b").unwrap();
        assert_eq!(key, "query");
        assert_eq!(value, Value::String("a=b".to_owned()));
    }

    #[test]
    fn parse_override_special_characters_in_value() {
        let (key, value) = parse_override("msg=hello & goodbye!").unwrap();
        assert_eq!(key, "msg");
        assert_eq!(value, Value::String("hello & goodbye!".to_owned()));
    }

    // ── Override application ────────────────────────────────────────────

    #[test]
    fn apply_top_level_override() {
        let input = json!({"title": "old", "body": "text"});
        let overrides = vec![("title".to_owned(), json!("new"))];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result["title"], json!("new"));
        assert_eq!(result["body"], json!("text"));
    }

    #[test]
    fn apply_nested_override() {
        let input = json!({"config": {"timeout": 30, "retry": true}});
        let overrides = vec![("config.timeout".to_owned(), json!(60))];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result["config"]["timeout"], json!(60));
        assert_eq!(result["config"]["retry"], json!(true));
    }

    #[test]
    fn apply_deeply_nested_override() {
        let input = json!({"a": {"b": {"c": 1}}});
        let overrides = vec![("a.b.c".to_owned(), json!(99))];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result["a"]["b"]["c"], json!(99));
    }

    #[test]
    fn apply_override_creates_missing_path() {
        let input = json!({"title": "hi"});
        let overrides = vec![("config.timeout".to_owned(), json!(30))];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result["config"]["timeout"], json!(30));
        assert_eq!(result["title"], json!("hi"));
    }

    #[test]
    fn apply_override_with_array_value() {
        let input = json!({"labels": ["old"]});
        let overrides = vec![("labels".to_owned(), json!(["new1", "new2"]))];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result["labels"], json!(["new1", "new2"]));
    }

    #[test]
    fn apply_override_to_null_creates_object() {
        let input = Value::Null;
        let overrides = vec![("key".to_owned(), json!("value"))];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result["key"], json!("value"));
    }

    #[test]
    fn apply_override_nested_null_creates_path() {
        let input = json!({"outer": null});
        let overrides = vec![("outer.inner".to_owned(), json!(42))];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result["outer"]["inner"], json!(42));
    }

    #[test]
    fn apply_multiple_overrides() {
        let input = json!({"a": 1, "b": 2, "c": 3});
        let overrides = vec![("a".to_owned(), json!(10)), ("b".to_owned(), json!(20))];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result["a"], json!(10));
        assert_eq!(result["b"], json!(20));
        assert_eq!(result["c"], json!(3));
    }

    #[test]
    fn apply_empty_overrides() {
        let input = json!({"a": 1});
        let overrides: Vec<(String, Value)> = vec![];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn apply_override_refuses_traverse_non_object() {
        let input = json!({"name": "text"});
        let overrides = vec![("name.sub".to_owned(), json!(1))];
        let result = apply_overrides(&input, &overrides);
        assert!(result.is_err());
    }

    #[test]
    fn apply_override_adds_new_top_level_key() {
        let input = json!({"existing": true});
        let overrides = vec![("new_key".to_owned(), json!("new_value"))];
        let result = apply_overrides(&input, &overrides).unwrap();
        assert_eq!(result["existing"], json!(true));
        assert_eq!(result["new_key"], json!("new_value"));
    }

    // ── ReplayPlan generation ───────────────────────────────────────────

    #[test]
    fn plan_basic_replay() {
        let store = temp_store();
        let input = sample_input();
        let mut history = HistoryStore::new();

        let entry = sample_history_entry("e001");
        history.append(entry);
        store
            .store_input("e001", "github", "issues.create", &input)
            .unwrap();

        let request = ReplayRequest::simple("e001");
        let plan = plan_replay(&request, &store, &history).unwrap();

        assert_eq!(plan.connector_id, "github");
        assert_eq!(plan.operation_id, "issues.create");
        assert_eq!(plan.effective_input, input);
        assert!(plan.overrides_applied.is_empty());
        assert!(!plan.dry_run);
    }

    #[test]
    fn plan_replay_with_overrides() {
        let store = temp_store();
        let input = sample_input();
        let mut history = HistoryStore::new();

        history.append(sample_history_entry("e001"));
        store
            .store_input("e001", "github", "issues.create", &input)
            .unwrap();

        let request = ReplayRequest::simple("e001").with_override("title", json!("Updated Title"));
        let plan = plan_replay(&request, &store, &history).unwrap();

        assert_eq!(plan.effective_input["title"], json!("Updated Title"));
        assert_eq!(plan.effective_input["body"], json!("Some content"));
        assert!(plan.overrides_applied.contains(&"title".to_owned()));
    }

    #[test]
    fn plan_replay_dry_run() {
        let store = temp_store();
        let input = sample_input();
        let mut history = HistoryStore::new();

        history.append(sample_history_entry("e001"));
        store
            .store_input("e001", "github", "issues.create", &input)
            .unwrap();

        let request = ReplayRequest::simple("e001").dry_run();
        let plan = plan_replay(&request, &store, &history).unwrap();
        assert!(plan.dry_run);
    }

    #[test]
    fn plan_replay_missing_entry() {
        let store = temp_store();
        let history = HistoryStore::new();
        let request = ReplayRequest::simple("e999");
        let result = plan_replay(&request, &store, &history);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn plan_replay_input_not_stored() {
        let store = temp_store();
        let mut history = HistoryStore::new();
        history.append(sample_history_entry("e001"));

        let request = ReplayRequest::simple("e001");
        let result = plan_replay(&request, &store, &history);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no stored input"));
    }

    // ── find_last_of ────────────────────────────────────────────────────

    #[test]
    fn find_last_of_returns_most_recent() {
        let mut history = HistoryStore::new();

        let mut e1 = sample_history_entry("e001");
        e1.invoked_at = "2026-01-01T00:00:00Z".to_owned();
        history.append(e1);

        let mut e2 = sample_history_entry("e002");
        e2.invoked_at = "2026-01-02T00:00:00Z".to_owned();
        history.append(e2);

        let found = find_last_of("issues.create", &history).unwrap();
        // Most recent should be e002 (appended last, reversed in query).
        assert_eq!(found.entry_id, "e002");
    }

    #[test]
    fn find_last_of_no_match() {
        let history = HistoryStore::new();
        assert!(find_last_of("nonexistent.op", &history).is_none());
    }

    #[test]
    fn find_last_of_filters_by_operation() {
        let mut history = HistoryStore::new();

        let e1 = sample_history_entry("e001"); // issues.create
        history.append(e1);

        let mut e2 = sample_history_entry("e002");
        e2.operation_id = "repos.list".to_owned();
        history.append(e2);

        let found = find_last_of("repos.list", &history).unwrap();
        assert_eq!(found.entry_id, "e002");
    }

    // ── HistoryStore ────────────────────────────────────────────────────

    #[test]
    fn history_store_append_and_get() {
        let mut store = HistoryStore::new();
        let entry = sample_history_entry("e001");
        store.append(entry);

        assert_eq!(store.count(), 1);
        let got = store.get("e001").unwrap();
        assert_eq!(got.connector_id, "github");
    }

    #[test]
    fn history_store_get_missing() {
        let store = HistoryStore::new();
        assert!(store.get("nope").is_none());
    }

    #[test]
    fn history_store_query_by_connector() {
        let mut store = HistoryStore::new();
        store.append(sample_history_entry("e001"));

        let mut e2 = sample_history_entry("e002");
        e2.connector_id = "slack".to_owned();
        store.append(e2);

        let filter = HistoryFilter {
            connector_id: Some("slack".to_owned()),
            ..HistoryFilter::default()
        };
        let results = store.query(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, "e002");
    }

    #[test]
    fn history_store_query_by_status() {
        let mut store = HistoryStore::new();
        store.append(sample_history_entry("e001")); // Success

        let mut e2 = sample_history_entry("e002");
        e2.status = OpStatus::Failure;
        store.append(e2);

        let filter = HistoryFilter {
            status: Some(OpStatus::Failure),
            ..HistoryFilter::default()
        };
        let results = store.query(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, "e002");
    }

    #[test]
    fn history_store_query_with_limit() {
        let mut store = HistoryStore::new();
        for i in 0..10 {
            let entry = sample_history_entry(&format!("e{i:03}"));
            store.append(entry);
        }

        let filter = HistoryFilter {
            limit: Some(3),
            ..HistoryFilter::default()
        };
        let results = store.query(&filter);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn history_store_empty_count() {
        let store = HistoryStore::new();
        assert_eq!(store.count(), 0);
    }

    // ── content_hash / summarize_input ──────────────────────────────────

    #[test]
    fn content_hash_deterministic() {
        let input = json!({"a": 1, "b": 2});
        let h1 = content_hash(&input);
        let h2 = content_hash(&input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_differs_for_different_input() {
        let h1 = content_hash(&json!({"a": 1}));
        let h2 = content_hash(&json!({"a": 2}));
        assert_ne!(h1, h2);
    }

    #[test]
    fn summarize_input_object() {
        let input = json!({"title": "hi", "body": "text"});
        let summary = summarize_input(&input);
        assert!(summary.contains("title"));
        assert!(summary.contains("body"));
    }

    #[test]
    fn summarize_input_array() {
        let input = json!([1, 2, 3]);
        let summary = summarize_input(&input);
        assert!(summary.contains("3 items"));
    }

    #[test]
    fn summarize_input_string() {
        let input = json!("hello");
        let summary = summarize_input(&input);
        assert!(summary.contains("hello"));
    }

    #[test]
    fn summarize_input_long_string_truncated() {
        let long = "a".repeat(100);
        let input = Value::String(long);
        let summary = summarize_input(&input);
        assert!(summary.contains("..."));
        assert!(summary.len() < 60);
    }

    #[test]
    fn summarize_input_object_many_keys() {
        let input = json!({"a": 1, "b": 2, "c": 3, "d": 4, "e": 5});
        let summary = summarize_input(&input);
        assert!(summary.contains("5 keys"));
    }

    // ── Serialization round-trips ───────────────────────────────────────

    #[test]
    fn stored_input_disk_roundtrip() {
        let stored = StoredInput {
            entry_id: "e001".to_owned(),
            connector_id: "github".to_owned(),
            operation_id: "issues.create".to_owned(),
            input: sample_input(),
            stored_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + Duration::days(7)).to_rfc3339(),
        };

        let disk = StoredInputDisk::from_stored(&stored).unwrap();
        let recovered = disk.into_stored().unwrap();

        assert_eq!(recovered.entry_id, stored.entry_id);
        assert_eq!(recovered.connector_id, stored.connector_id);
        assert_eq!(recovered.operation_id, stored.operation_id);
        assert_eq!(recovered.input, stored.input);
    }

    #[test]
    fn replay_request_serialization_roundtrip() {
        let request = ReplayRequest::simple("e001")
            .with_override("title", json!("updated"))
            .dry_run();

        let json = serde_json::to_string(&request).unwrap();
        let recovered: ReplayRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(recovered.entry_id, "e001");
        assert!(recovered.dry_run);
        assert_eq!(recovered.overrides["title"], json!("updated"));
    }

    #[test]
    fn replay_plan_serialization_roundtrip() {
        let plan = ReplayPlan {
            original: StoredInput {
                entry_id: "e001".to_owned(),
                connector_id: "github".to_owned(),
                operation_id: "issues.create".to_owned(),
                input: json!({"title": "old"}),
                stored_at: Utc::now().to_rfc3339(),
                expires_at: (Utc::now() + Duration::days(7)).to_rfc3339(),
            },
            effective_input: json!({"title": "new"}),
            overrides_applied: vec!["title".to_owned()],
            connector_id: "github".to_owned(),
            operation_id: "issues.create".to_owned(),
            dry_run: false,
        };

        let json = serde_json::to_string(&plan).unwrap();
        let recovered: ReplayPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.connector_id, "github");
        assert_eq!(recovered.effective_input["title"], json!("new"));
    }

    #[test]
    fn op_status_display() {
        assert_eq!(OpStatus::Success.to_string(), "success");
        assert_eq!(OpStatus::Failure.to_string(), "failure");
        assert_eq!(OpStatus::Denied.to_string(), "denied");
        assert_eq!(OpStatus::Timeout.to_string(), "timeout");
    }

    #[test]
    fn op_status_serde_roundtrip() {
        let statuses = [
            OpStatus::Success,
            OpStatus::Failure,
            OpStatus::Denied,
            OpStatus::Timeout,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let recovered: OpStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, status);
        }
    }

    // ── ReplayError display ─────────────────────────────────────────────

    #[test]
    fn replay_error_display_entry_not_found() {
        let err = ReplayError::EntryNotFound {
            entry_id: "e001".to_owned(),
        };
        assert!(err.to_string().contains("e001"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn replay_error_display_input_expired() {
        let err = ReplayError::InputExpired {
            entry_id: "e001".to_owned(),
            expired_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn replay_error_display_input_not_stored() {
        let err = ReplayError::InputNotStored {
            entry_id: "e001".to_owned(),
        };
        assert!(err.to_string().contains("no stored input"));
    }

    #[test]
    fn replay_error_display_invalid_override() {
        let err = ReplayError::InvalidOverride {
            raw: "bad".to_owned(),
            reason: "missing `=`".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad"));
        assert!(msg.contains("missing"));
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn store_input_with_special_chars_in_id() {
        let store = temp_store();
        let input = json!({"key": "value"});
        // Colons get replaced with underscores in file names.
        store
            .store_input("w:abc:123", "github", "issues.create", &input)
            .unwrap();
        let stored = store.get_stored_input("w:abc:123").unwrap().unwrap();
        assert_eq!(stored.entry_id, "w:abc:123");
    }

    #[test]
    fn base64_encoding_preserves_unicode() {
        let store = temp_store();
        let input = json!({"greeting": "Hello, world!"});
        store
            .store_input("e-unicode", "test", "op", &input)
            .unwrap();
        let stored = store.get_stored_input("e-unicode").unwrap().unwrap();
        assert_eq!(stored.input["greeting"], json!("Hello, world!"));
    }

    #[test]
    fn base64_encoding_preserves_nested_structure() {
        let store = temp_store();
        let input = json!({
            "a": {"b": {"c": [1, 2, {"d": true}]}},
            "e": null
        });
        store.store_input("e-nested", "test", "op", &input).unwrap();
        let stored = store.get_stored_input("e-nested").unwrap().unwrap();
        assert_eq!(stored.input, input);
    }

    #[test]
    fn content_hash_empty_object() {
        let h = content_hash(&json!({}));
        assert!(!h.is_empty());
    }

    #[test]
    fn content_hash_null() {
        let h = content_hash(&Value::Null);
        assert!(!h.is_empty());
    }

    #[test]
    fn replay_request_with_multiple_overrides() {
        let request = ReplayRequest::simple("e001")
            .with_override("a", json!(1))
            .with_override("b", json!(2))
            .with_override("c.d", json!(3));

        assert_eq!(request.overrides.len(), 3);
        assert_eq!(request.overrides["a"], json!(1));
        assert_eq!(request.overrides["c.d"], json!(3));
    }

    #[test]
    fn history_filter_default_matches_all() {
        let mut store = HistoryStore::new();
        store.append(sample_history_entry("e001"));
        store.append(sample_history_entry("e002"));

        let results = store.query(&HistoryFilter::default());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn replay_error_serde_roundtrip() {
        let errors = vec![
            ReplayError::EntryNotFound {
                entry_id: "e1".to_owned(),
            },
            ReplayError::InputExpired {
                entry_id: "e2".to_owned(),
                expired_at: "now".to_owned(),
            },
            ReplayError::InputNotStored {
                entry_id: "e3".to_owned(),
            },
            ReplayError::InvalidOverride {
                raw: "bad".to_owned(),
                reason: "missing =".to_owned(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let recovered: ReplayError = serde_json::from_str(&json).unwrap();
            assert_eq!(&recovered, err);
        }
    }

    #[test]
    fn history_query_combined_filters() {
        let mut store = HistoryStore::new();

        let mut e1 = sample_history_entry("e001");
        e1.connector_id = "github".to_owned();
        e1.status = OpStatus::Success;
        store.append(e1);

        let mut e2 = sample_history_entry("e002");
        e2.connector_id = "github".to_owned();
        e2.status = OpStatus::Failure;
        store.append(e2);

        let mut e3 = sample_history_entry("e003");
        e3.connector_id = "slack".to_owned();
        e3.status = OpStatus::Success;
        store.append(e3);

        let filter = HistoryFilter {
            connector_id: Some("github".to_owned()),
            status: Some(OpStatus::Success),
            ..HistoryFilter::default()
        };
        let results = store.query(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, "e001");
    }

    #[test]
    fn plan_replay_with_nested_overrides() {
        let store = temp_store();
        let input = json!({"config": {"timeout": 30, "retry": true}, "title": "hi"});
        let mut history = HistoryStore::new();

        history.append(sample_history_entry("e001"));
        store
            .store_input("e001", "github", "issues.create", &input)
            .unwrap();

        let request = ReplayRequest::simple("e001")
            .with_override("config.timeout", json!(120))
            .with_override("title", json!("updated"));
        let plan = plan_replay(&request, &store, &history).unwrap();

        assert_eq!(plan.effective_input["config"]["timeout"], json!(120));
        assert_eq!(plan.effective_input["config"]["retry"], json!(true));
        assert_eq!(plan.effective_input["title"], json!("updated"));
        assert_eq!(plan.overrides_applied.len(), 2);
    }
}
