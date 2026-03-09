//! Checkpoint management for event stream consumption.
//!
//! Enables resume-from-position and time-range replay so that event consumers
//! can pick up where they left off after restarts or failures.
//!
//! Each connector's checkpoint is persisted as a JSON file under a configurable
//! directory (defaulting to `~/.fwc/checkpoints/`). Writes are atomic:
//! data is written to a temporary file and then renamed to the final path,
//! preventing partial reads from concurrent consumers.

use std::fmt;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ── Core types ──────────────────────────────────────────────────────────────

/// Persisted checkpoint for a single connector's event stream position.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    /// Connector identifier (e.g. `"fcp.github"`).
    pub connector_id: String,
    /// Last consumed sequence number.
    pub last_sequence: u64,
    /// Timestamp of the last consumed event.
    pub last_timestamp: DateTime<Utc>,
    /// Optional opaque event identifier from the upstream source.
    pub last_event_id: Option<String>,
    /// When this checkpoint was last written.
    pub updated_at: DateTime<Utc>,
    /// Cumulative number of events consumed through this checkpoint.
    pub event_count: u64,
}

/// Incremental update supplied by an event consumer to advance the checkpoint.
#[derive(Clone, Debug)]
pub struct CheckpointUpdate {
    /// Sequence number of the newly consumed event.
    pub sequence: u64,
    /// Timestamp of the newly consumed event.
    pub timestamp: DateTime<Utc>,
    /// Optional event identifier.
    pub event_id: Option<String>,
}

// ── Replay types ────────────────────────────────────────────────────────────

/// Request to replay events for a connector.
#[derive(Clone, Debug)]
pub struct ReplayRequest {
    /// Target connector.
    pub connector_id: String,
    /// How to determine the starting point.
    pub mode: ReplayMode,
}

/// Strategy for determining where replay begins.
#[derive(Clone, Debug)]
pub enum ReplayMode {
    /// Resume from a checkpoint file at the given path.
    FromCheckpoint(PathBuf),
    /// Resume from a specific sequence number.
    FromSequence(u64),
    /// Replay events within a time window.
    TimeRange {
        from: DateTime<Utc>,
        to: Option<DateTime<Utc>>,
    },
    /// Start from the current tip — no historical replay.
    FromLatest,
}

/// Advertised replay capabilities of a connector.
#[derive(Clone, Debug)]
pub struct ReplayCapability {
    /// Connector identifier.
    pub connector_id: String,
    /// Whether the connector supports replaying from a sequence number.
    pub supports_sequence_replay: bool,
    /// Whether the connector supports replaying by time range.
    pub supports_time_replay: bool,
    /// Maximum lookback window the connector supports.
    pub max_replay_window: Option<Duration>,
}

/// The resolved replay instruction after capability negotiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedReplay {
    /// Start consuming from the given sequence number.
    StartFrom { sequence: u64 },
    /// Start consuming from a time boundary.
    StartFromTime {
        from: DateTime<Utc>,
        to: Option<DateTime<Utc>>,
    },
    /// Start from the latest position (no replay).
    StartFromLatest,
    /// The requested mode is unsupported; a fallback is provided.
    Unsupported {
        reason: String,
        fallback: Box<Self>,
    },
}

impl fmt::Display for ResolvedReplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartFrom { sequence } => write!(f, "start from sequence {sequence}"),
            Self::StartFromTime { from, to } => {
                write!(f, "start from time {from}")?;
                if let Some(to) = to {
                    write!(f, " to {to}")?;
                }
                Ok(())
            }
            Self::StartFromLatest => write!(f, "start from latest"),
            Self::Unsupported { reason, fallback } => {
                write!(f, "unsupported ({reason}), fallback: {fallback}")
            }
        }
    }
}

// ── CLI arg parsing ─────────────────────────────────────────────────────────

/// Raw CLI arguments for replay commands.
#[derive(Clone, Debug, Default)]
pub struct ReplayArgs {
    /// Path to a checkpoint file (`--checkpoint`).
    pub checkpoint: Option<PathBuf>,
    /// Sequence number (`--from-seq`).
    pub from_seq: Option<u64>,
    /// ISO-8601 start time (`--from`).
    pub from_time: Option<String>,
    /// ISO-8601 end time (`--to`).
    pub to_time: Option<String>,
}

/// Parse [`ReplayArgs`] into a [`ReplayMode`].
///
/// # Errors
///
/// Returns an error if conflicting options are specified or if timestamps
/// cannot be parsed.
pub fn parse_replay_mode(args: &ReplayArgs) -> Result<ReplayMode> {
    let mut mode_count = 0u32;
    if args.checkpoint.is_some() {
        mode_count += 1;
    }
    if args.from_seq.is_some() {
        mode_count += 1;
    }
    if args.from_time.is_some() {
        mode_count += 1;
    }

    if mode_count > 1 {
        bail!(
            "conflicting replay options: specify at most one of \
             --checkpoint, --from-seq, or --from"
        );
    }

    if let Some(ref path) = args.checkpoint {
        return Ok(ReplayMode::FromCheckpoint(path.clone()));
    }

    if let Some(seq) = args.from_seq {
        return Ok(ReplayMode::FromSequence(seq));
    }

    if let Some(ref from_str) = args.from_time {
        let from = from_str
            .parse::<DateTime<Utc>>()
            .with_context(|| format!("invalid --from timestamp: {from_str}"))?;
        let to = args
            .to_time
            .as_ref()
            .map(|s| {
                s.parse::<DateTime<Utc>>()
                    .with_context(|| format!("invalid --to timestamp: {s}"))
            })
            .transpose()?;
        return Ok(ReplayMode::TimeRange { from, to });
    }

    // If --to is specified alone, that's an error.
    if args.to_time.is_some() {
        bail!("--to requires --from to be specified");
    }

    Ok(ReplayMode::FromLatest)
}

// ── Checkpoint store ────────────────────────────────────────────────────────

/// File-backed checkpoint store.
///
/// Checkpoints are stored as `{connector_id}.json` under the configured
/// directory. All writes go through a temp-file-then-rename dance to
/// guarantee atomicity.
pub struct CheckpointStore {
    dir: PathBuf,
}

impl CheckpointStore {
    /// Create a new store rooted at `dir`.
    ///
    /// The directory is created lazily on the first write.
    #[must_use]
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Persist a checkpoint to disk atomically.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or the file cannot
    /// be written.
    pub fn save(&self, checkpoint: &Checkpoint) -> Result<()> {
        fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating checkpoint dir {}", self.dir.display()))?;

        let final_path = self.path_for(&checkpoint.connector_id);
        let tmp_path = self.tmp_path_for(&checkpoint.connector_id);

        let json = serde_json::to_string_pretty(checkpoint)
            .context("serializing checkpoint")?;
        fs::write(&tmp_path, json.as_bytes())
            .with_context(|| format!("writing temp checkpoint {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &final_path)
            .with_context(|| format!("renaming temp checkpoint to {}", final_path.display()))?;

        Ok(())
    }

    /// Load a checkpoint for the given connector, if one exists.
    ///
    /// Returns `Ok(None)` when no checkpoint file is found.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load(&self, connector_id: &str) -> Result<Option<Checkpoint>> {
        let path = self.path_for(connector_id);
        match fs::read_to_string(&path) {
            Ok(data) => {
                let cp: Checkpoint = serde_json::from_str(&data)
                    .with_context(|| format!("parsing checkpoint {}", path.display()))?;
                Ok(Some(cp))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::Error::new(e)
                .context(format!("reading checkpoint {}", path.display()))),
        }
    }

    /// Remove the checkpoint for a connector.
    ///
    /// Returns `true` if a checkpoint was actually deleted, `false` if none
    /// existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be removed.
    pub fn remove(&self, connector_id: &str) -> Result<bool> {
        let path = self.path_for(connector_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(anyhow::Error::new(e)
                .context(format!("removing checkpoint {}", path.display()))),
        }
    }

    /// List all persisted checkpoints.
    ///
    /// Silently skips files that cannot be parsed (e.g. corrupted).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read. Returns an empty
    /// vector if the directory does not exist.
    pub fn list(&self) -> Result<Vec<Checkpoint>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut checkpoints = Vec::new();
        let entries = fs::read_dir(&self.dir)
            .with_context(|| format!("listing checkpoints in {}", self.dir.display()))?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(data) = fs::read_to_string(&path) {
                    if let Ok(cp) = serde_json::from_str::<Checkpoint>(&data) {
                        checkpoints.push(cp);
                    }
                }
            }
        }
        checkpoints.sort_by(|a, b| a.connector_id.cmp(&b.connector_id));
        Ok(checkpoints)
    }

    /// Atomically update (or create) a checkpoint for the given connector.
    ///
    /// Loads the existing checkpoint, applies the update, and writes back.
    /// If no checkpoint exists, a new one is created starting from the update.
    ///
    /// # Errors
    ///
    /// Returns an error if load or save fails.
    pub fn update(&self, connector_id: &str, update: &CheckpointUpdate) -> Result<Checkpoint> {
        let now = Utc::now();
        let cp = match self.load(connector_id)? {
            Some(mut existing) => {
                existing.last_sequence = update.sequence;
                existing.last_timestamp = update.timestamp;
                existing.last_event_id.clone_from(&update.event_id);
                existing.updated_at = now;
                existing.event_count += 1;
                existing
            }
            None => Checkpoint {
                connector_id: connector_id.to_owned(),
                last_sequence: update.sequence,
                last_timestamp: update.timestamp,
                last_event_id: update.event_id.clone(),
                updated_at: now,
                event_count: 1,
            },
        };
        self.save(&cp)?;
        Ok(cp)
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn path_for(&self, connector_id: &str) -> PathBuf {
        self.dir.join(format!("{connector_id}.json"))
    }

    fn tmp_path_for(&self, connector_id: &str) -> PathBuf {
        let pid = std::process::id();
        self.dir.join(format!("{connector_id}.json.tmp.{pid}"))
    }
}

// ── Replay resolution ───────────────────────────────────────────────────────

/// Resolve a [`ReplayRequest`] against the store and connector capabilities.
///
/// When the requested mode is unsupported by the connector an
/// [`ResolvedReplay::Unsupported`] variant is returned, carrying a human
/// readable reason and a best-effort fallback.
///
/// # Errors
///
/// Returns an error on I/O failures (e.g. unreadable checkpoint file).
pub fn resolve_replay_mode(
    request: &ReplayRequest,
    store: &CheckpointStore,
    capability: &ReplayCapability,
) -> Result<ResolvedReplay> {
    match &request.mode {
        ReplayMode::FromLatest => Ok(ResolvedReplay::StartFromLatest),

        ReplayMode::FromSequence(seq) => {
            if capability.supports_sequence_replay {
                Ok(ResolvedReplay::StartFrom { sequence: *seq })
            } else {
                Ok(ResolvedReplay::Unsupported {
                    reason: format!(
                        "connector {} does not support sequence replay",
                        capability.connector_id
                    ),
                    fallback: Box::new(ResolvedReplay::StartFromLatest),
                })
            }
        }

        ReplayMode::TimeRange { from, to } => {
            if !capability.supports_time_replay {
                return Ok(ResolvedReplay::Unsupported {
                    reason: format!(
                        "connector {} does not support time-based replay",
                        capability.connector_id
                    ),
                    fallback: Box::new(ResolvedReplay::StartFromLatest),
                });
            }

            // Check if the requested window exceeds the maximum.
            if let Some(max_window) = capability.max_replay_window {
                let effective_to = to.unwrap_or_else(Utc::now);
                let window = effective_to.signed_duration_since(*from);
                if window > max_window {
                    let clamped_from = effective_to - max_window;
                    return Ok(ResolvedReplay::Unsupported {
                        reason: format!(
                            "requested window ({} seconds) exceeds maximum ({} seconds)",
                            window.num_seconds(),
                            max_window.num_seconds(),
                        ),
                        fallback: Box::new(ResolvedReplay::StartFromTime {
                            from: clamped_from,
                            to: *to,
                        }),
                    });
                }
            }

            Ok(ResolvedReplay::StartFromTime {
                from: *from,
                to: *to,
            })
        }

        ReplayMode::FromCheckpoint(path) => {
            // If the path points to a file, load it directly.
            // Otherwise, fall back to the store.
            let cp = if path.is_file() {
                let data = fs::read_to_string(path)
                    .with_context(|| format!("reading checkpoint file {}", path.display()))?;
                serde_json::from_str::<Checkpoint>(&data)
                    .with_context(|| format!("parsing checkpoint file {}", path.display()))?
            } else {
                // Try the store with the connector_id from the request.
                match store.load(&request.connector_id)? {
                    Some(cp) => cp,
                    None => return Ok(ResolvedReplay::StartFromLatest),
                }
            };

            if capability.supports_sequence_replay {
                Ok(ResolvedReplay::StartFrom {
                    sequence: cp.last_sequence,
                })
            } else if capability.supports_time_replay {
                Ok(ResolvedReplay::StartFromTime {
                    from: cp.last_timestamp,
                    to: None,
                })
            } else {
                Ok(ResolvedReplay::Unsupported {
                    reason: format!(
                        "connector {} supports neither sequence nor time replay",
                        capability.connector_id
                    ),
                    fallback: Box::new(ResolvedReplay::StartFromLatest),
                })
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("fwc-checkpoint-tests")
            .join(name)
            .join(format!("{}", std::process::id()));
        if dir.exists() {
            let _ = fs::remove_dir_all(&dir);
        }
        dir
    }

    fn sample_checkpoint(id: &str) -> Checkpoint {
        Checkpoint {
            connector_id: id.to_owned(),
            last_sequence: 42,
            last_timestamp: Utc::now(),
            last_event_id: Some("evt-001".to_owned()),
            updated_at: Utc::now(),
            event_count: 10,
        }
    }

    fn sample_update(seq: u64) -> CheckpointUpdate {
        CheckpointUpdate {
            sequence: seq,
            timestamp: Utc::now(),
            event_id: None,
        }
    }

    fn full_capability(id: &str) -> ReplayCapability {
        ReplayCapability {
            connector_id: id.to_owned(),
            supports_sequence_replay: true,
            supports_time_replay: true,
            max_replay_window: None,
        }
    }

    // ── CheckpointStore: save/load round-trip ───────────────────────────

    #[test]
    fn store_save_load_roundtrip() {
        let dir = temp_dir("save_load");
        let store = CheckpointStore::new(dir);
        let cp = sample_checkpoint("fcp.github");
        store.save(&cp).unwrap();
        let loaded = store.load("fcp.github").unwrap().unwrap();
        assert_eq!(cp, loaded);
    }

    #[test]
    fn store_load_missing_returns_none() {
        let dir = temp_dir("load_missing");
        let store = CheckpointStore::new(dir);
        let result = store.load("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn store_save_creates_directory() {
        let dir = temp_dir("save_creates_dir");
        assert!(!dir.exists());
        let store = CheckpointStore::new(dir.clone());
        store.save(&sample_checkpoint("fcp.test")).unwrap();
        assert!(dir.exists());
    }

    #[test]
    fn store_save_overwrites_existing() {
        let dir = temp_dir("save_overwrite");
        let store = CheckpointStore::new(dir);
        let mut cp = sample_checkpoint("fcp.github");
        store.save(&cp).unwrap();
        cp.last_sequence = 99;
        cp.event_count = 20;
        store.save(&cp).unwrap();
        let loaded = store.load("fcp.github").unwrap().unwrap();
        assert_eq!(loaded.last_sequence, 99);
        assert_eq!(loaded.event_count, 20);
    }

    // ── CheckpointStore: remove ─────────────────────────────────────────

    #[test]
    fn store_remove_existing() {
        let dir = temp_dir("remove_existing");
        let store = CheckpointStore::new(dir);
        store.save(&sample_checkpoint("fcp.github")).unwrap();
        assert!(store.remove("fcp.github").unwrap());
        assert!(store.load("fcp.github").unwrap().is_none());
    }

    #[test]
    fn store_remove_nonexistent_returns_false() {
        let dir = temp_dir("remove_nonexist");
        let store = CheckpointStore::new(dir);
        assert!(!store.remove("nope").unwrap());
    }

    // ── CheckpointStore: list ───────────────────────────────────────────

    #[test]
    fn store_list_empty() {
        let dir = temp_dir("list_empty");
        let store = CheckpointStore::new(dir);
        let list = store.list().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn store_list_multiple() {
        let dir = temp_dir("list_multiple");
        let store = CheckpointStore::new(dir);
        store.save(&sample_checkpoint("fcp.alpha")).unwrap();
        store.save(&sample_checkpoint("fcp.beta")).unwrap();
        store.save(&sample_checkpoint("fcp.gamma")).unwrap();
        let list = store.list().unwrap();
        assert_eq!(list.len(), 3);
        // Sorted alphabetically.
        assert_eq!(list[0].connector_id, "fcp.alpha");
        assert_eq!(list[1].connector_id, "fcp.beta");
        assert_eq!(list[2].connector_id, "fcp.gamma");
    }

    #[test]
    fn store_list_skips_corrupted_files() {
        let dir = temp_dir("list_corrupted");
        let store = CheckpointStore::new(dir.clone());
        store.save(&sample_checkpoint("fcp.good")).unwrap();
        // Write a corrupt file.
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("fcp.bad.json"), "NOT VALID JSON!!!").unwrap();
        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].connector_id, "fcp.good");
    }

    #[test]
    fn store_list_ignores_non_json_files() {
        let dir = temp_dir("list_non_json");
        let store = CheckpointStore::new(dir.clone());
        store.save(&sample_checkpoint("fcp.valid")).unwrap();
        fs::write(dir.join("notes.txt"), "hello").unwrap();
        fs::write(dir.join("backup.bak"), "{}").unwrap();
        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
    }

    // ── CheckpointStore: update ─────────────────────────────────────────

    #[test]
    fn store_update_creates_new() {
        let dir = temp_dir("update_new");
        let store = CheckpointStore::new(dir);
        let up = sample_update(1);
        let cp = store.update("fcp.new", &up).unwrap();
        assert_eq!(cp.connector_id, "fcp.new");
        assert_eq!(cp.last_sequence, 1);
        assert_eq!(cp.event_count, 1);
    }

    #[test]
    fn store_update_increments_existing() {
        let dir = temp_dir("update_incr");
        let store = CheckpointStore::new(dir);
        store.update("fcp.inc", &sample_update(1)).unwrap();
        store.update("fcp.inc", &sample_update(2)).unwrap();
        let cp = store.update("fcp.inc", &sample_update(3)).unwrap();
        assert_eq!(cp.last_sequence, 3);
        assert_eq!(cp.event_count, 3);
    }

    #[test]
    fn store_update_preserves_connector_id() {
        let dir = temp_dir("update_id");
        let store = CheckpointStore::new(dir);
        let cp = store.update("fcp.preserve", &sample_update(5)).unwrap();
        assert_eq!(cp.connector_id, "fcp.preserve");
    }

    #[test]
    fn store_update_sets_event_id() {
        let dir = temp_dir("update_eid");
        let store = CheckpointStore::new(dir);
        let up = CheckpointUpdate {
            sequence: 7,
            timestamp: Utc::now(),
            event_id: Some("e-abc".to_owned()),
        };
        let cp = store.update("fcp.eid", &up).unwrap();
        assert_eq!(cp.last_event_id.as_deref(), Some("e-abc"));
    }

    #[test]
    fn store_update_clears_event_id() {
        let dir = temp_dir("update_clear_eid");
        let store = CheckpointStore::new(dir);
        let up1 = CheckpointUpdate {
            sequence: 1,
            timestamp: Utc::now(),
            event_id: Some("e-first".to_owned()),
        };
        store.update("fcp.clr", &up1).unwrap();
        let up2 = CheckpointUpdate {
            sequence: 2,
            timestamp: Utc::now(),
            event_id: None,
        };
        let cp = store.update("fcp.clr", &up2).unwrap();
        assert!(cp.last_event_id.is_none());
    }

    // ── Atomic writes ───────────────────────────────────────────────────

    #[test]
    fn atomic_write_no_leftover_tmp() {
        let dir = temp_dir("atomic_no_tmp");
        let store = CheckpointStore::new(dir.clone());
        store.save(&sample_checkpoint("fcp.atomic")).unwrap();
        // No tmp files should remain.
        let entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.path()
                    .to_string_lossy()
                    .contains(".tmp.")
            })
            .collect();
        assert!(entries.is_empty(), "temp files should not remain after save");
    }

    #[test]
    fn atomic_write_tmp_path_contains_pid() {
        let store = CheckpointStore::new(PathBuf::from("/fake"));
        let tmp = store.tmp_path_for("fcp.test");
        let pid = std::process::id();
        assert!(
            tmp.to_string_lossy().contains(&format!(".tmp.{pid}")),
            "temp path should include PID"
        );
    }

    // ── Serialization round-trip ────────────────────────────────────────

    #[test]
    fn checkpoint_json_roundtrip() {
        let cp = sample_checkpoint("fcp.serde");
        let json = serde_json::to_string(&cp).unwrap();
        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(cp, deserialized);
    }

    #[test]
    fn checkpoint_pretty_json_roundtrip() {
        let cp = sample_checkpoint("fcp.pretty");
        let json = serde_json::to_string_pretty(&cp).unwrap();
        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(cp, deserialized);
    }

    #[test]
    fn checkpoint_without_event_id_roundtrip() {
        let cp = Checkpoint {
            connector_id: "fcp.no-eid".to_owned(),
            last_sequence: 0,
            last_timestamp: Utc::now(),
            last_event_id: None,
            updated_at: Utc::now(),
            event_count: 0,
        };
        let json = serde_json::to_string(&cp).unwrap();
        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(cp, deserialized);
    }

    // ── ReplayMode parsing ──────────────────────────────────────────────

    #[test]
    fn parse_latest_when_no_args() {
        let args = ReplayArgs::default();
        let mode = parse_replay_mode(&args).unwrap();
        assert!(matches!(mode, ReplayMode::FromLatest));
    }

    #[test]
    fn parse_from_checkpoint() {
        let args = ReplayArgs {
            checkpoint: Some(PathBuf::from("/tmp/cp.json")),
            ..Default::default()
        };
        let mode = parse_replay_mode(&args).unwrap();
        assert!(matches!(mode, ReplayMode::FromCheckpoint(_)));
    }

    #[test]
    fn parse_from_sequence() {
        let args = ReplayArgs {
            from_seq: Some(100),
            ..Default::default()
        };
        let mode = parse_replay_mode(&args).unwrap();
        assert!(matches!(mode, ReplayMode::FromSequence(100)));
    }

    #[test]
    fn parse_time_range_from_only() {
        let args = ReplayArgs {
            from_time: Some("2026-01-01T00:00:00Z".to_owned()),
            ..Default::default()
        };
        let mode = parse_replay_mode(&args).unwrap();
        match mode {
            ReplayMode::TimeRange { to, .. } => assert!(to.is_none()),
            other => panic!("expected TimeRange, got {other:?}"),
        }
    }

    #[test]
    fn parse_time_range_from_and_to() {
        let args = ReplayArgs {
            from_time: Some("2026-01-01T00:00:00Z".to_owned()),
            to_time: Some("2026-01-02T00:00:00Z".to_owned()),
            ..Default::default()
        };
        let mode = parse_replay_mode(&args).unwrap();
        match mode {
            ReplayMode::TimeRange { to, .. } => assert!(to.is_some()),
            other => panic!("expected TimeRange, got {other:?}"),
        }
    }

    #[test]
    fn parse_conflicting_checkpoint_and_seq() {
        let args = ReplayArgs {
            checkpoint: Some(PathBuf::from("/tmp/cp.json")),
            from_seq: Some(10),
            ..Default::default()
        };
        assert!(parse_replay_mode(&args).is_err());
    }

    #[test]
    fn parse_conflicting_seq_and_time() {
        let args = ReplayArgs {
            from_seq: Some(10),
            from_time: Some("2026-01-01T00:00:00Z".to_owned()),
            ..Default::default()
        };
        assert!(parse_replay_mode(&args).is_err());
    }

    #[test]
    fn parse_conflicting_all_three() {
        let args = ReplayArgs {
            checkpoint: Some(PathBuf::from("/tmp/cp.json")),
            from_seq: Some(10),
            from_time: Some("2026-01-01T00:00:00Z".to_owned()),
            ..Default::default()
        };
        assert!(parse_replay_mode(&args).is_err());
    }

    #[test]
    fn parse_to_without_from_fails() {
        let args = ReplayArgs {
            to_time: Some("2026-01-02T00:00:00Z".to_owned()),
            ..Default::default()
        };
        assert!(parse_replay_mode(&args).is_err());
    }

    #[test]
    fn parse_invalid_from_timestamp() {
        let args = ReplayArgs {
            from_time: Some("not-a-date".to_owned()),
            ..Default::default()
        };
        assert!(parse_replay_mode(&args).is_err());
    }

    #[test]
    fn parse_invalid_to_timestamp() {
        let args = ReplayArgs {
            from_time: Some("2026-01-01T00:00:00Z".to_owned()),
            to_time: Some("also-not-a-date".to_owned()),
            ..Default::default()
        };
        assert!(parse_replay_mode(&args).is_err());
    }

    // ── Replay resolution ───────────────────────────────────────────────

    #[test]
    fn resolve_latest() {
        let dir = temp_dir("resolve_latest");
        let store = CheckpointStore::new(dir);
        let req = ReplayRequest {
            connector_id: "fcp.test".to_owned(),
            mode: ReplayMode::FromLatest,
        };
        let cap = full_capability("fcp.test");
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert_eq!(resolved, ResolvedReplay::StartFromLatest);
    }

    #[test]
    fn resolve_from_sequence_supported() {
        let dir = temp_dir("resolve_seq_ok");
        let store = CheckpointStore::new(dir);
        let req = ReplayRequest {
            connector_id: "fcp.test".to_owned(),
            mode: ReplayMode::FromSequence(42),
        };
        let cap = full_capability("fcp.test");
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert_eq!(resolved, ResolvedReplay::StartFrom { sequence: 42 });
    }

    #[test]
    fn resolve_from_sequence_unsupported() {
        let dir = temp_dir("resolve_seq_unsup");
        let store = CheckpointStore::new(dir);
        let req = ReplayRequest {
            connector_id: "fcp.test".to_owned(),
            mode: ReplayMode::FromSequence(42),
        };
        let cap = ReplayCapability {
            connector_id: "fcp.test".to_owned(),
            supports_sequence_replay: false,
            supports_time_replay: true,
            max_replay_window: None,
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert!(matches!(resolved, ResolvedReplay::Unsupported { .. }));
    }

    #[test]
    fn resolve_time_range_supported() {
        let dir = temp_dir("resolve_time_ok");
        let store = CheckpointStore::new(dir);
        let from = "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let req = ReplayRequest {
            connector_id: "fcp.test".to_owned(),
            mode: ReplayMode::TimeRange { from, to: None },
        };
        let cap = full_capability("fcp.test");
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert_eq!(
            resolved,
            ResolvedReplay::StartFromTime { from, to: None }
        );
    }

    #[test]
    fn resolve_time_range_unsupported() {
        let dir = temp_dir("resolve_time_unsup");
        let store = CheckpointStore::new(dir);
        let from = "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let req = ReplayRequest {
            connector_id: "fcp.test".to_owned(),
            mode: ReplayMode::TimeRange { from, to: None },
        };
        let cap = ReplayCapability {
            connector_id: "fcp.test".to_owned(),
            supports_sequence_replay: true,
            supports_time_replay: false,
            max_replay_window: None,
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert!(matches!(resolved, ResolvedReplay::Unsupported { .. }));
    }

    #[test]
    fn resolve_time_range_exceeds_max_window() {
        let dir = temp_dir("resolve_time_max");
        let store = CheckpointStore::new(dir);
        let from = "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let to = "2026-02-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let req = ReplayRequest {
            connector_id: "fcp.test".to_owned(),
            mode: ReplayMode::TimeRange {
                from,
                to: Some(to),
            },
        };
        let cap = ReplayCapability {
            connector_id: "fcp.test".to_owned(),
            supports_sequence_replay: false,
            supports_time_replay: true,
            max_replay_window: Some(Duration::hours(24)),
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        match resolved {
            ResolvedReplay::Unsupported { reason, fallback } => {
                assert!(reason.contains("exceeds maximum"));
                assert!(matches!(*fallback, ResolvedReplay::StartFromTime { .. }));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn resolve_time_range_within_window() {
        let dir = temp_dir("resolve_time_within");
        let store = CheckpointStore::new(dir);
        let now = Utc::now();
        let from = now - Duration::hours(1);
        let req = ReplayRequest {
            connector_id: "fcp.test".to_owned(),
            mode: ReplayMode::TimeRange {
                from,
                to: Some(now),
            },
        };
        let cap = ReplayCapability {
            connector_id: "fcp.test".to_owned(),
            supports_sequence_replay: false,
            supports_time_replay: true,
            max_replay_window: Some(Duration::hours(24)),
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert!(matches!(resolved, ResolvedReplay::StartFromTime { .. }));
    }

    #[test]
    fn resolve_from_checkpoint_file_sequence() {
        let dir = temp_dir("resolve_cp_file_seq");
        let store = CheckpointStore::new(dir.clone());
        // Write a checkpoint file at a custom path.
        let cp = sample_checkpoint("fcp.file");
        fs::create_dir_all(&dir).unwrap();
        let cp_path = dir.join("custom.json");
        fs::write(&cp_path, serde_json::to_string(&cp).unwrap()).unwrap();

        let req = ReplayRequest {
            connector_id: "fcp.file".to_owned(),
            mode: ReplayMode::FromCheckpoint(cp_path),
        };
        let cap = full_capability("fcp.file");
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert_eq!(resolved, ResolvedReplay::StartFrom { sequence: 42 });
    }

    #[test]
    fn resolve_from_checkpoint_file_time_fallback() {
        let dir = temp_dir("resolve_cp_file_time");
        let store = CheckpointStore::new(dir.clone());
        let cp = sample_checkpoint("fcp.file");
        fs::create_dir_all(&dir).unwrap();
        let cp_path = dir.join("custom.json");
        fs::write(&cp_path, serde_json::to_string(&cp).unwrap()).unwrap();

        let req = ReplayRequest {
            connector_id: "fcp.file".to_owned(),
            mode: ReplayMode::FromCheckpoint(cp_path),
        };
        let cap = ReplayCapability {
            connector_id: "fcp.file".to_owned(),
            supports_sequence_replay: false,
            supports_time_replay: true,
            max_replay_window: None,
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert!(matches!(resolved, ResolvedReplay::StartFromTime { .. }));
    }

    #[test]
    fn resolve_from_checkpoint_store_fallback() {
        let dir = temp_dir("resolve_cp_store");
        let store = CheckpointStore::new(dir);
        store.save(&sample_checkpoint("fcp.stored")).unwrap();
        let req = ReplayRequest {
            connector_id: "fcp.stored".to_owned(),
            mode: ReplayMode::FromCheckpoint(PathBuf::from("/nonexistent/checkpoint.json")),
        };
        let cap = full_capability("fcp.stored");
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert_eq!(resolved, ResolvedReplay::StartFrom { sequence: 42 });
    }

    #[test]
    fn resolve_from_checkpoint_nothing_found() {
        let dir = temp_dir("resolve_cp_nothing");
        let store = CheckpointStore::new(dir);
        let req = ReplayRequest {
            connector_id: "fcp.nope".to_owned(),
            mode: ReplayMode::FromCheckpoint(PathBuf::from("/nonexistent/cp.json")),
        };
        let cap = full_capability("fcp.nope");
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert_eq!(resolved, ResolvedReplay::StartFromLatest);
    }

    #[test]
    fn resolve_from_checkpoint_no_replay_support() {
        let dir = temp_dir("resolve_cp_nosup");
        let store = CheckpointStore::new(dir.clone());
        let cp = sample_checkpoint("fcp.nosup");
        fs::create_dir_all(&dir).unwrap();
        let cp_path = dir.join("nosup.json");
        fs::write(&cp_path, serde_json::to_string(&cp).unwrap()).unwrap();

        let req = ReplayRequest {
            connector_id: "fcp.nosup".to_owned(),
            mode: ReplayMode::FromCheckpoint(cp_path),
        };
        let cap = ReplayCapability {
            connector_id: "fcp.nosup".to_owned(),
            supports_sequence_replay: false,
            supports_time_replay: false,
            max_replay_window: None,
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert!(matches!(resolved, ResolvedReplay::Unsupported { .. }));
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn large_sequence_number() {
        let dir = temp_dir("large_seq");
        let store = CheckpointStore::new(dir);
        let up = CheckpointUpdate {
            sequence: u64::MAX,
            timestamp: Utc::now(),
            event_id: None,
        };
        let cp = store.update("fcp.huge", &up).unwrap();
        assert_eq!(cp.last_sequence, u64::MAX);
        // Verify it survives round-trip through JSON.
        let loaded = store.load("fcp.huge").unwrap().unwrap();
        assert_eq!(loaded.last_sequence, u64::MAX);
    }

    #[test]
    fn empty_connector_id() {
        let dir = temp_dir("empty_id");
        let store = CheckpointStore::new(dir);
        let cp = sample_checkpoint("");
        store.save(&cp).unwrap();
        let loaded = store.load("").unwrap().unwrap();
        assert_eq!(loaded.connector_id, "");
    }

    #[test]
    fn store_update_advances_timestamp() {
        let dir = temp_dir("advance_ts");
        let store = CheckpointStore::new(dir);
        let t1 = "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let t2 = "2026-06-15T12:30:00Z".parse::<DateTime<Utc>>().unwrap();
        let up1 = CheckpointUpdate {
            sequence: 1,
            timestamp: t1,
            event_id: None,
        };
        let up2 = CheckpointUpdate {
            sequence: 2,
            timestamp: t2,
            event_id: None,
        };
        store.update("fcp.ts", &up1).unwrap();
        let cp = store.update("fcp.ts", &up2).unwrap();
        assert_eq!(cp.last_timestamp, t2);
    }

    #[test]
    fn corrupted_checkpoint_file_load_error() {
        let dir = temp_dir("corrupt_load");
        let store = CheckpointStore::new(dir.clone());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("fcp.corrupt.json"), "{{{{not json}}}}").unwrap();
        let result = store.load("fcp.corrupt");
        assert!(result.is_err());
    }

    #[test]
    fn resolved_replay_display_start_from() {
        let r = ResolvedReplay::StartFrom { sequence: 10 };
        assert_eq!(r.to_string(), "start from sequence 10");
    }

    #[test]
    fn resolved_replay_display_latest() {
        let r = ResolvedReplay::StartFromLatest;
        assert_eq!(r.to_string(), "start from latest");
    }

    #[test]
    fn resolved_replay_display_unsupported() {
        let r = ResolvedReplay::Unsupported {
            reason: "no seq support".to_owned(),
            fallback: Box::new(ResolvedReplay::StartFromLatest),
        };
        let s = r.to_string();
        assert!(s.contains("unsupported"));
        assert!(s.contains("no seq support"));
        assert!(s.contains("start from latest"));
    }

    #[test]
    fn resolved_replay_display_time_range_open() {
        let from = "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let r = ResolvedReplay::StartFromTime { from, to: None };
        let s = r.to_string();
        assert!(s.contains("start from time"));
        assert!(!s.contains(" to "));
    }

    #[test]
    fn resolved_replay_display_time_range_closed() {
        let from = "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let to = "2026-01-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let r = ResolvedReplay::StartFromTime {
            from,
            to: Some(to),
        };
        let s = r.to_string();
        assert!(s.contains("start from time"));
        assert!(s.contains(" to "));
    }

    // ── ReplayCapability combinations ───────────────────────────────────

    #[test]
    fn capability_seq_only() {
        let dir = temp_dir("cap_seq_only");
        let store = CheckpointStore::new(dir);
        let cap = ReplayCapability {
            connector_id: "fcp.seq".to_owned(),
            supports_sequence_replay: true,
            supports_time_replay: false,
            max_replay_window: None,
        };
        let req = ReplayRequest {
            connector_id: "fcp.seq".to_owned(),
            mode: ReplayMode::FromSequence(5),
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert_eq!(resolved, ResolvedReplay::StartFrom { sequence: 5 });
    }

    #[test]
    fn capability_time_only() {
        let dir = temp_dir("cap_time_only");
        let store = CheckpointStore::new(dir);
        let cap = ReplayCapability {
            connector_id: "fcp.time".to_owned(),
            supports_sequence_replay: false,
            supports_time_replay: true,
            max_replay_window: None,
        };
        let from = "2026-03-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let req = ReplayRequest {
            connector_id: "fcp.time".to_owned(),
            mode: ReplayMode::TimeRange { from, to: None },
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert!(matches!(resolved, ResolvedReplay::StartFromTime { .. }));
    }

    #[test]
    fn capability_neither() {
        let dir = temp_dir("cap_neither");
        let store = CheckpointStore::new(dir);
        let cap = ReplayCapability {
            connector_id: "fcp.none".to_owned(),
            supports_sequence_replay: false,
            supports_time_replay: false,
            max_replay_window: None,
        };
        let req = ReplayRequest {
            connector_id: "fcp.none".to_owned(),
            mode: ReplayMode::FromSequence(1),
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert!(matches!(resolved, ResolvedReplay::Unsupported { .. }));
    }

    #[test]
    fn capability_both_prefers_sequence_for_checkpoint() {
        let dir = temp_dir("cap_both_seq");
        let store = CheckpointStore::new(dir.clone());
        let cp = sample_checkpoint("fcp.both");
        fs::create_dir_all(&dir).unwrap();
        let cp_path = dir.join("both.json");
        fs::write(&cp_path, serde_json::to_string(&cp).unwrap()).unwrap();

        let cap = full_capability("fcp.both");
        let req = ReplayRequest {
            connector_id: "fcp.both".to_owned(),
            mode: ReplayMode::FromCheckpoint(cp_path),
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        // When both are supported, sequence is preferred.
        assert!(matches!(resolved, ResolvedReplay::StartFrom { .. }));
    }

    // ── Additional edge cases ───────────────────────────────────────────

    #[test]
    fn multiple_updates_different_connectors() {
        let dir = temp_dir("multi_conn");
        let store = CheckpointStore::new(dir);
        store.update("fcp.a", &sample_update(10)).unwrap();
        store.update("fcp.b", &sample_update(20)).unwrap();
        store.update("fcp.c", &sample_update(30)).unwrap();

        let a = store.load("fcp.a").unwrap().unwrap();
        let b = store.load("fcp.b").unwrap().unwrap();
        let c = store.load("fcp.c").unwrap().unwrap();
        assert_eq!(a.last_sequence, 10);
        assert_eq!(b.last_sequence, 20);
        assert_eq!(c.last_sequence, 30);
    }

    #[test]
    fn save_and_remove_then_list() {
        let dir = temp_dir("save_rm_list");
        let store = CheckpointStore::new(dir);
        store.save(&sample_checkpoint("fcp.keep")).unwrap();
        store.save(&sample_checkpoint("fcp.drop")).unwrap();
        store.remove("fcp.drop").unwrap();
        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].connector_id, "fcp.keep");
    }

    #[test]
    fn checkpoint_zero_event_count() {
        let cp = Checkpoint {
            connector_id: "fcp.zero".to_owned(),
            last_sequence: 0,
            last_timestamp: Utc::now(),
            last_event_id: None,
            updated_at: Utc::now(),
            event_count: 0,
        };
        let json = serde_json::to_string(&cp).unwrap();
        let rt: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.event_count, 0);
        assert_eq!(rt.last_sequence, 0);
    }

    #[test]
    fn max_replay_window_none_means_unlimited() {
        let dir = temp_dir("window_none");
        let store = CheckpointStore::new(dir);
        let cap = ReplayCapability {
            connector_id: "fcp.unlimited".to_owned(),
            supports_sequence_replay: false,
            supports_time_replay: true,
            max_replay_window: None, // no limit
        };
        // A very large window should succeed.
        let from = "2020-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let to = "2026-12-31T23:59:59Z".parse::<DateTime<Utc>>().unwrap();
        let req = ReplayRequest {
            connector_id: "fcp.unlimited".to_owned(),
            mode: ReplayMode::TimeRange {
                from,
                to: Some(to),
            },
        };
        let resolved = resolve_replay_mode(&req, &store, &cap).unwrap();
        assert!(matches!(resolved, ResolvedReplay::StartFromTime { .. }));
    }
}
