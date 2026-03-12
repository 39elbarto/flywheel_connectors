//! Agent session registration and context persistence.
//!
//! Tracks agent identity, goals, and arbitrary context across context rotations.
//! Sessions are stored as JSON files in `~/.fwc/sessions/`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// A unique session identifier, displayed as `s:<short_hex>`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Create a new random session ID.
    pub fn generate() -> Self {
        let id = Uuid::new_v4();
        Self(format!("s:{}", &id.simple().to_string()[..8]))
    }

    /// Parse from a string like `"s:deadbeef"`.
    pub fn parse(s: &str) -> Option<Self> {
        if s.starts_with("s:") && s.len() > 2 {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The short hex portion after the `s:` prefix.
    pub fn short_id(&self) -> &str {
        self.0.strip_prefix("s:").unwrap_or(&self.0)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Session status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Paused,
    Ended,
}

impl SessionStatus {
    /// Return the canonical status tag used by the CLI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Ended => "ended",
        }
    }

    /// Parse a CLI status selector.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            "ended" => Some(Self::Ended),
            _ => None,
        }
    }
}

/// An agent session with identity and context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub agent_name: String,
    pub goal: String,
    pub status: SessionStatus,
    pub zone: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    /// Count of operations completed in this session.
    pub operations_completed: u64,
    /// Arbitrary key-value context that persists across context rotations.
    pub context: BTreeMap<String, Value>,
}

impl Session {
    /// Create a new active session.
    pub fn new(
        agent_name: impl Into<String>,
        goal: impl Into<String>,
        zone: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::generate(),
            agent_name: agent_name.into(),
            goal: goal.into(),
            status: SessionStatus::Active,
            zone,
            created_at: now,
            updated_at: now,
            ended_at: None,
            operations_completed: 0,
            context: BTreeMap::new(),
        }
    }

    /// End this session.
    pub fn end(&mut self) {
        let now = Utc::now();
        self.status = SessionStatus::Ended;
        self.ended_at = Some(now);
        self.updated_at = now;
    }

    /// Pause this session.
    pub fn pause(&mut self) {
        self.status = SessionStatus::Paused;
        self.updated_at = Utc::now();
    }

    /// Resume a paused session.
    pub fn resume(&mut self) {
        self.status = SessionStatus::Active;
        self.ended_at = None;
        self.updated_at = Utc::now();
    }

    /// Set a context key.
    pub fn set_context(&mut self, key: impl Into<String>, value: Value) {
        self.context.insert(key.into(), value);
        self.updated_at = Utc::now();
    }

    /// Get a context value.
    pub fn get_context(&self, key: &str) -> Option<&Value> {
        self.context.get(key)
    }

    /// Increment the operations counter.
    pub fn record_operation(&mut self) {
        self.operations_completed += 1;
        self.updated_at = Utc::now();
    }

    /// Whether this session is still active.
    pub fn is_active(&self) -> bool {
        self.status == SessionStatus::Active
    }
}

/// File-backed session store in `~/.fwc/sessions/`.
pub struct SessionStore {
    dir: PathBuf,
}

impl SessionStore {
    /// Create a store at the default location.
    pub fn default_path() -> Self {
        if let Ok(dir) = std::env::var("FWC_SESSION_DIR") {
            return Self {
                dir: PathBuf::from(dir),
            };
        }
        let home = std::env::var("HOME").map_or_else(|_| PathBuf::from("."), PathBuf::from);
        let dir = home.join(".fwc").join("sessions");
        Self { dir }
    }

    /// Create a store at a custom path (for testing).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Save a session to disk.
    pub fn save(&self, session: &Session) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.session_path(&session.id);
        let json = serde_json::to_string_pretty(session)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load a session by ID.
    pub fn load(&self, id: &SessionId) -> anyhow::Result<Option<Session>> {
        let path = self.session_path(id);
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(path)?;
        let session: Session = serde_json::from_str(&json)?;
        Ok(Some(session))
    }

    /// Resolve a short or fully-prefixed session ID and load it from disk.
    pub fn load_resolved(&self, input: &str) -> anyhow::Result<Option<Session>> {
        let Some(id) = resolve_session_id(input) else {
            return Ok(None);
        };
        self.load(&id)
    }

    /// List all sessions, sorted by last updated (most recent first).
    pub fn list(&self, status_filter: Option<SessionStatus>) -> anyhow::Result<Vec<Session>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut sessions = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                if let Ok(json) = std::fs::read_to_string(&path) {
                    if let Ok(session) = serde_json::from_str::<Session>(&json) {
                        if let Some(filter) = status_filter {
                            if session.status == filter {
                                sessions.push(session);
                            }
                        } else {
                            sessions.push(session);
                        }
                    }
                }
            }
        }
        sessions.sort_by_key(|s| std::cmp::Reverse(s.updated_at));
        Ok(sessions)
    }

    /// Find the most recent active session.
    pub fn active_session(&self) -> anyhow::Result<Option<Session>> {
        let sessions = self.list(Some(SessionStatus::Active))?;
        Ok(sessions.into_iter().next())
    }

    /// Delete a session file.
    pub fn delete(&self, id: &SessionId) -> anyhow::Result<bool> {
        let path = self.session_path(id);
        if path.exists() {
            std::fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// The root directory used for persisted sessions.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn session_path(&self, id: &SessionId) -> PathBuf {
        self.dir.join(format!("{}.json", id.short_id()))
    }
}

/// Resolve a session ID from user input.
///
/// Accepts `"s:deadbeef"` or just `"deadbeef"`.
pub fn resolve_session_id(input: &str) -> Option<SessionId> {
    if input.starts_with("s:") {
        SessionId::parse(input)
    } else {
        SessionId::parse(&format!("s:{input}"))
    }
}

/// Compute session file path from base directory.
pub fn session_dir(base: &Path) -> PathBuf {
    base.join("sessions")
}

#[cfg(test)]
mod tests {
    use super::*;

    static SESSION_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn temp_store() -> SessionStore {
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fwc-session-test-{unique}"));
        SessionStore::new(dir.join("sessions"))
    }

    // ── SessionId ───────────────────────────────────────────────────

    #[test]
    fn session_id_generate_format() {
        let id = SessionId::generate();
        assert!(id.as_str().starts_with("s:"));
        assert_eq!(id.short_id().len(), 8);
    }

    #[test]
    fn session_id_parse_valid() {
        let id = SessionId::parse("s:deadbeef").unwrap();
        assert_eq!(id.short_id(), "deadbeef");
    }

    #[test]
    fn session_id_parse_invalid() {
        assert!(SessionId::parse("deadbeef").is_none());
        assert!(SessionId::parse("s:").is_none());
        assert!(SessionId::parse("").is_none());
    }

    #[test]
    fn session_id_display() {
        let id = SessionId::parse("s:abc12345").unwrap();
        assert_eq!(format!("{id}"), "s:abc12345");
    }

    // ── Session ─────────────────────────────────────────────────────

    #[test]
    fn new_session_is_active() {
        let session = Session::new("TestAgent", "test goal", None);
        assert!(session.is_active());
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.operations_completed, 0);
    }

    #[test]
    fn session_lifecycle() {
        let mut session = Session::new("Agent", "goal", Some("z:work".into()));
        assert!(session.is_active());

        session.pause();
        assert_eq!(session.status, SessionStatus::Paused);
        assert!(!session.is_active());

        session.resume();
        assert!(session.is_active());

        session.end();
        assert_eq!(session.status, SessionStatus::Ended);
        assert!(session.ended_at.is_some());
    }

    #[test]
    fn session_context() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("key", serde_json::json!("value"));
        assert_eq!(
            session.get_context("key"),
            Some(&serde_json::json!("value"))
        );
        assert_eq!(session.get_context("missing"), None);
    }

    #[test]
    fn session_operations_counter() {
        let mut session = Session::new("Agent", "goal", None);
        session.record_operation();
        session.record_operation();
        assert_eq!(session.operations_completed, 2);
    }

    #[test]
    fn session_serde_round_trip() {
        let mut session = Session::new("Agent", "goal", Some("z:test".into()));
        session.set_context("key", serde_json::json!(42));
        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.agent_name, "Agent");
        assert_eq!(restored.goal, "goal");
        assert_eq!(restored.zone, Some("z:test".into()));
        assert_eq!(restored.get_context("key"), Some(&serde_json::json!(42)));
    }

    // ── SessionStore ────────────────────────────────────────────────

    #[test]
    fn store_save_and_load() {
        let store = temp_store();
        let session = Session::new("Agent", "goal", None);
        let id = session.id.clone();
        store.save(&session).unwrap();

        let loaded = store.load(&id).unwrap().unwrap();
        assert_eq!(loaded.agent_name, "Agent");
        assert_eq!(loaded.goal, "goal");
    }

    #[test]
    fn store_load_missing() {
        let store = temp_store();
        let id = SessionId::parse("s:nonexist").unwrap();
        assert!(store.load(&id).unwrap().is_none());
    }

    #[test]
    fn store_list_all() {
        let store = temp_store();
        let s1 = Session::new("A", "g1", None);
        let s2 = Session::new("B", "g2", None);
        store.save(&s1).unwrap();
        store.save(&s2).unwrap();

        let sessions = store.list(None).unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn store_list_filtered_by_status() {
        let store = temp_store();
        let s1 = Session::new("A", "g1", None);
        let mut s2 = Session::new("B", "g2", None);
        s2.end();
        store.save(&s1).unwrap();
        store.save(&s2).unwrap();

        let active = store.list(Some(SessionStatus::Active)).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].agent_name, "A");

        let ended = store.list(Some(SessionStatus::Ended)).unwrap();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].agent_name, "B");
    }

    #[test]
    fn store_active_session() {
        let store = temp_store();
        let session = Session::new("Agent", "goal", None);
        store.save(&session).unwrap();

        let active = store.active_session().unwrap().unwrap();
        assert_eq!(active.agent_name, "Agent");
    }

    #[test]
    fn store_delete() {
        let store = temp_store();
        let session = Session::new("Agent", "goal", None);
        let id = session.id.clone();
        store.save(&session).unwrap();

        assert!(store.delete(&id).unwrap());
        assert!(store.load(&id).unwrap().is_none());
        assert!(!store.delete(&id).unwrap()); // already deleted
    }

    #[test]
    fn store_empty_list() {
        let store = temp_store();
        let sessions = store.list(None).unwrap();
        assert!(sessions.is_empty());
    }

    // ── resolve_session_id ──────────────────────────────────────────

    #[test]
    fn resolve_with_prefix() {
        let id = resolve_session_id("s:abc12345").unwrap();
        assert_eq!(id.as_str(), "s:abc12345");
    }

    #[test]
    fn resolve_without_prefix() {
        let id = resolve_session_id("abc12345").unwrap();
        assert_eq!(id.as_str(), "s:abc12345");
    }

    // ── Determinism ─────────────────────────────────────────────────

    #[test]
    fn list_sorted_by_updated_at() {
        let store = temp_store();
        let s1 = Session::new("First", "g1", None);
        store.save(&s1).unwrap();

        // Create second session slightly later.
        let s2 = Session::new("Second", "g2", None);
        store.save(&s2).unwrap();

        let sessions = store.list(None).unwrap();
        // Most recently updated should come first.
        assert!(sessions[0].updated_at >= sessions[1].updated_at);
    }

    // ── Additional SessionId tests ─────────────────────────────────

    #[test]
    fn session_id_generate_unique() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn session_id_as_str_matches_display() {
        let id = SessionId::parse("s:cafebabe").unwrap();
        assert_eq!(id.as_str(), &format!("{id}"));
    }

    #[test]
    fn session_id_clone_equality() {
        let id = SessionId::parse("s:deadbeef").unwrap();
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn session_id_parse_long_hex() {
        let id = SessionId::parse("s:aabbccdd11223344").unwrap();
        assert_eq!(id.short_id(), "aabbccdd11223344");
    }

    #[test]
    fn session_id_parse_single_char() {
        let id = SessionId::parse("s:a").unwrap();
        assert_eq!(id.short_id(), "a");
    }

    #[test]
    fn session_id_serde_roundtrip() {
        let id = SessionId::parse("s:abcdef01").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let restored: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, id);
    }

    #[test]
    fn session_id_serde_json_value() {
        let id = SessionId::parse("s:face1234").unwrap();
        let val = serde_json::to_value(&id).unwrap();
        assert_eq!(val, serde_json::json!("s:face1234"));
    }

    #[test]
    fn session_id_debug_format() {
        let id = SessionId::parse("s:abc").unwrap();
        let debug = format!("{id:?}");
        assert!(debug.contains("s:abc"));
    }

    // ── Additional Session tests ───────────────────────────────────

    #[test]
    fn session_new_with_zone() {
        let session = Session::new("Agent", "goal", Some("zone:prod".to_string()));
        assert_eq!(session.zone.as_deref(), Some("zone:prod"));
    }

    #[test]
    fn session_new_without_zone() {
        let session = Session::new("Agent", "goal", None);
        assert!(session.zone.is_none());
    }

    #[test]
    fn session_created_at_equals_updated_at_initially() {
        let session = Session::new("Agent", "goal", None);
        assert_eq!(session.created_at, session.updated_at);
    }

    #[test]
    fn session_end_sets_ended_at() {
        let mut session = Session::new("Agent", "goal", None);
        assert!(session.ended_at.is_none());
        session.end();
        assert!(session.ended_at.is_some());
    }

    #[test]
    fn session_pause_does_not_set_ended_at() {
        let mut session = Session::new("Agent", "goal", None);
        session.pause();
        assert!(session.ended_at.is_none());
    }

    #[test]
    fn session_resume_after_end_makes_active() {
        let mut session = Session::new("Agent", "goal", None);
        session.end();
        session.resume();
        assert!(session.is_active());
    }

    #[test]
    fn session_context_overwrite() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("key", serde_json::json!("first"));
        session.set_context("key", serde_json::json!("second"));
        assert_eq!(
            session.get_context("key"),
            Some(&serde_json::json!("second"))
        );
    }

    #[test]
    fn session_context_multiple_keys() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("a", serde_json::json!(1));
        session.set_context("b", serde_json::json!(2));
        session.set_context("c", serde_json::json!(3));
        assert_eq!(session.context.len(), 3);
    }

    #[test]
    fn session_context_complex_value() {
        let mut session = Session::new("Agent", "goal", None);
        let complex = serde_json::json!({
            "nested": {"deep": true},
            "list": [1, 2, 3]
        });
        session.set_context("data", complex.clone());
        assert_eq!(session.get_context("data"), Some(&complex));
    }

    #[test]
    fn session_operations_counter_starts_at_zero() {
        let session = Session::new("Agent", "goal", None);
        assert_eq!(session.operations_completed, 0);
    }

    #[test]
    fn session_record_many_operations() {
        let mut session = Session::new("Agent", "goal", None);
        for _ in 0..100 {
            session.record_operation();
        }
        assert_eq!(session.operations_completed, 100);
    }

    #[test]
    fn session_serde_with_ended_session() {
        let mut session = Session::new("Agent", "goal", Some("z:dev".into()));
        session.record_operation();
        session.set_context("foo", serde_json::json!("bar"));
        session.end();
        let json = serde_json::to_string_pretty(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.status, SessionStatus::Ended);
        assert!(restored.ended_at.is_some());
        assert_eq!(restored.operations_completed, 1);
    }

    #[test]
    fn session_serde_with_paused_session() {
        let mut session = Session::new("Agent", "goal", None);
        session.pause();
        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.status, SessionStatus::Paused);
    }

    // ── Additional SessionStatus tests ─────────────────────────────

    #[test]
    fn session_status_serde_active() {
        let json = serde_json::to_string(&SessionStatus::Active).unwrap();
        assert_eq!(json, "\"active\"");
        let back: SessionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SessionStatus::Active);
    }

    #[test]
    fn session_status_serde_paused() {
        let json = serde_json::to_string(&SessionStatus::Paused).unwrap();
        assert_eq!(json, "\"paused\"");
    }

    #[test]
    fn session_status_serde_ended() {
        let json = serde_json::to_string(&SessionStatus::Ended).unwrap();
        assert_eq!(json, "\"ended\"");
    }

    #[test]
    fn session_status_equality() {
        assert_eq!(SessionStatus::Active, SessionStatus::Active);
        assert_ne!(SessionStatus::Active, SessionStatus::Paused);
        assert_ne!(SessionStatus::Paused, SessionStatus::Ended);
    }

    #[test]
    fn session_status_clone() {
        let status = SessionStatus::Active;
        let cloned = status;
        assert_eq!(status, cloned);
    }

    #[test]
    fn session_status_parse_round_trip() {
        for status in [
            SessionStatus::Active,
            SessionStatus::Paused,
            SessionStatus::Ended,
        ] {
            assert_eq!(SessionStatus::parse(status.as_str()), Some(status));
        }
        assert!(SessionStatus::parse("invalid").is_none());
    }

    // ── Additional SessionStore tests ──────────────────────────────

    #[test]
    fn store_save_multiple_and_load_each() {
        let store = temp_store();
        let sessions: Vec<Session> = (0..5)
            .map(|i| Session::new(format!("Agent{i}"), format!("goal{i}"), None))
            .collect();

        for s in &sessions {
            store.save(s).unwrap();
        }

        for s in &sessions {
            let loaded = store.load(&s.id).unwrap().unwrap();
            assert_eq!(loaded.agent_name, s.agent_name);
        }
    }

    #[test]
    fn store_overwrite_session() {
        let store = temp_store();
        let mut session = Session::new("Agent", "goal v1", None);
        let id = session.id.clone();
        store.save(&session).unwrap();

        session.goal = "goal v2".to_string();
        store.save(&session).unwrap();

        let loaded = store.load(&id).unwrap().unwrap();
        assert_eq!(loaded.goal, "goal v2");
    }

    #[test]
    fn store_list_paused_filter() {
        let store = temp_store();
        let s1 = Session::new("A", "g1", None);
        let mut s2 = Session::new("B", "g2", None);
        s2.pause();
        store.save(&s1).unwrap();
        store.save(&s2).unwrap();

        let paused = store.list(Some(SessionStatus::Paused)).unwrap();
        assert_eq!(paused.len(), 1);
        assert_eq!(paused[0].agent_name, "B");
    }

    #[test]
    fn store_no_active_session_when_empty() {
        let store = temp_store();
        assert!(store.active_session().unwrap().is_none());
    }

    #[test]
    fn store_no_active_when_all_ended() {
        let store = temp_store();
        let mut s = Session::new("Agent", "goal", None);
        s.end();
        store.save(&s).unwrap();
        assert!(store.active_session().unwrap().is_none());
    }

    #[test]
    fn store_delete_nonexistent() {
        let store = temp_store();
        let id = SessionId::parse("s:nonexist").unwrap();
        assert!(!store.delete(&id).unwrap());
    }

    #[test]
    fn store_load_resolved_accepts_short_id() {
        let store = temp_store();
        let session = Session::new("Agent", "goal", None);
        let short_id = session.id.short_id().to_string();
        store.save(&session).unwrap();

        let loaded = store.load_resolved(&short_id).unwrap().unwrap();
        assert_eq!(loaded.id, session.id);
    }

    #[test]
    fn store_path_contains_short_id() {
        let store = temp_store();
        let session = Session::new("Agent", "goal", None);
        let id = session.id.clone();
        store.save(&session).unwrap();
        let expected_file = format!("{}.json", id.short_id());
        // Verify the file exists at the expected path
        let loaded = store.load(&id).unwrap();
        assert!(loaded.is_some());
        // The session path should use the short_id
        assert!(
            std::path::Path::new(&expected_file)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        );
    }

    // ── Additional resolve_session_id tests ────────────────────────

    #[test]
    fn resolve_empty_string() {
        // "s:" + "" = "s:" which has len 2 but s: prefix, so parse returns None for len <= 2
        // Actually "s:" has exactly 2 chars, so parse returns None
        let result = resolve_session_id("");
        // "s:" is len 2, parse requires len > 2
        assert!(result.is_none());
    }

    #[test]
    fn resolve_with_long_id() {
        let id = resolve_session_id("aabbccddeeff0011").unwrap();
        assert_eq!(id.as_str(), "s:aabbccddeeff0011");
    }

    #[test]
    fn resolve_preserves_exact_prefix() {
        let id = resolve_session_id("s:xyz").unwrap();
        assert_eq!(id.short_id(), "xyz");
    }

    // ── session_dir helper ─────────────────────────────────────────

    #[test]
    #[allow(unsafe_code)]
    fn default_path_prefers_env_override() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let _guard = SESSION_ENV_LOCK.lock().unwrap();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let override_dir = std::env::temp_dir().join(format!("fwc-session-env-{unique}"));

        // SAFETY: test-only env manipulation under SESSION_ENV_LOCK.
        unsafe {
            std::env::set_var("FWC_SESSION_DIR", &override_dir);
        }
        let store = SessionStore::default_path();
        // SAFETY: test-only cleanup under SESSION_ENV_LOCK.
        unsafe {
            std::env::remove_var("FWC_SESSION_DIR");
        }

        assert_eq!(store.dir(), override_dir.as_path());
    }

    #[test]
    fn session_dir_appends_sessions() {
        let base = Path::new("/home/user/.fwc");
        let dir = session_dir(base);
        assert_eq!(dir, PathBuf::from("/home/user/.fwc/sessions"));
    }

    #[test]
    fn session_dir_relative_path() {
        let base = Path::new(".");
        let dir = session_dir(base);
        assert_eq!(dir, PathBuf::from("./sessions"));
    }

    // ── Extended SessionId tests ──────────────────────────────────

    #[test]
    fn session_id_short_id_fallback_when_no_prefix() {
        // Construct a SessionId without the s: prefix via serde
        let id: SessionId = serde_json::from_str("\"raw_id\"").unwrap();
        // short_id uses strip_prefix which returns the full string on no match
        assert_eq!(id.short_id(), "raw_id");
    }

    #[test]
    fn session_id_as_str_returns_inner() {
        let id = SessionId::parse("s:hello").unwrap();
        assert_eq!(id.as_str(), "s:hello");
    }

    #[test]
    fn session_id_parse_rejects_colon_only() {
        assert!(SessionId::parse(":").is_none());
    }

    #[test]
    fn session_id_parse_rejects_wrong_prefix() {
        assert!(SessionId::parse("x:abc").is_none());
    }

    #[test]
    fn session_id_parse_accepts_special_chars() {
        let id = SessionId::parse("s:a-b_c.d").unwrap();
        assert_eq!(id.short_id(), "a-b_c.d");
    }

    #[test]
    fn session_id_generate_has_correct_total_len() {
        let id = SessionId::generate();
        // "s:" (2 chars) + 8 hex chars = 10 total
        assert_eq!(id.as_str().len(), 10);
    }

    #[test]
    fn session_id_display_is_same_as_inner() {
        let id = SessionId::parse("s:testid99").unwrap();
        let display = id.to_string();
        assert_eq!(display, "s:testid99");
        assert_eq!(display, id.as_str());
    }

    #[test]
    fn session_id_ne_for_different_ids() {
        let a = SessionId::parse("s:aaa").unwrap();
        let b = SessionId::parse("s:bbb").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn session_id_debug_includes_struct_name() {
        let id = SessionId::parse("s:test").unwrap();
        let debug = format!("{id:?}");
        assert!(debug.contains("SessionId"));
    }

    #[test]
    fn session_id_serde_deserialize_string() {
        let id: SessionId = serde_json::from_str("\"s:fromjson\"").unwrap();
        assert_eq!(id.as_str(), "s:fromjson");
    }

    // ── Extended SessionStatus tests ──────────────────────────────

    #[test]
    fn session_status_as_str_active() {
        assert_eq!(SessionStatus::Active.as_str(), "active");
    }

    #[test]
    fn session_status_as_str_paused() {
        assert_eq!(SessionStatus::Paused.as_str(), "paused");
    }

    #[test]
    fn session_status_as_str_ended() {
        assert_eq!(SessionStatus::Ended.as_str(), "ended");
    }

    #[test]
    fn session_status_parse_active() {
        assert_eq!(SessionStatus::parse("active"), Some(SessionStatus::Active));
    }

    #[test]
    fn session_status_parse_paused() {
        assert_eq!(SessionStatus::parse("paused"), Some(SessionStatus::Paused));
    }

    #[test]
    fn session_status_parse_ended() {
        assert_eq!(SessionStatus::parse("ended"), Some(SessionStatus::Ended));
    }

    #[test]
    fn session_status_parse_unknown() {
        assert!(SessionStatus::parse("running").is_none());
        assert!(SessionStatus::parse("").is_none());
        assert!(SessionStatus::parse("Active").is_none()); // case sensitive
        assert!(SessionStatus::parse("ACTIVE").is_none());
    }

    #[test]
    fn session_status_copy_semantics() {
        let a = SessionStatus::Paused;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn session_status_debug() {
        let d = format!("{:?}", SessionStatus::Active);
        assert_eq!(d, "Active");
        let d = format!("{:?}", SessionStatus::Paused);
        assert_eq!(d, "Paused");
        let d = format!("{:?}", SessionStatus::Ended);
        assert_eq!(d, "Ended");
    }

    #[test]
    fn session_status_serde_roundtrip_all() {
        for status in [
            SessionStatus::Active,
            SessionStatus::Paused,
            SessionStatus::Ended,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: SessionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn session_status_serde_invalid_variant() {
        let result = serde_json::from_str::<SessionStatus>("\"running\"");
        assert!(result.is_err());
    }

    // ── Extended Session tests ────────────────────────────────────

    #[test]
    fn session_agent_name_accepts_string_type() {
        let session = Session::new(String::from("OwnedAgent"), "goal", None);
        assert_eq!(session.agent_name, "OwnedAgent");
    }

    #[test]
    fn session_goal_accepts_string_type() {
        let session = Session::new("Agent", String::from("owned goal"), None);
        assert_eq!(session.goal, "owned goal");
    }

    #[test]
    fn session_end_updates_status_to_ended() {
        let mut session = Session::new("Agent", "goal", None);
        session.end();
        assert_eq!(session.status, SessionStatus::Ended);
        assert!(!session.is_active());
    }

    #[test]
    fn session_end_updates_updated_at() {
        let mut session = Session::new("Agent", "goal", None);
        let before = session.updated_at;
        // small busy wait to ensure time moves
        std::thread::sleep(std::time::Duration::from_millis(2));
        session.end();
        assert!(session.updated_at >= before);
    }

    #[test]
    fn session_pause_updates_updated_at() {
        let mut session = Session::new("Agent", "goal", None);
        let before = session.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(2));
        session.pause();
        assert!(session.updated_at >= before);
    }

    #[test]
    fn session_resume_updates_updated_at() {
        let mut session = Session::new("Agent", "goal", None);
        session.pause();
        let before = session.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(2));
        session.resume();
        assert!(session.updated_at >= before);
    }

    #[test]
    fn session_set_context_updates_updated_at() {
        let mut session = Session::new("Agent", "goal", None);
        let before = session.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(2));
        session.set_context("k", serde_json::json!(1));
        assert!(session.updated_at >= before);
    }

    #[test]
    fn session_record_operation_updates_updated_at() {
        let mut session = Session::new("Agent", "goal", None);
        let before = session.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(2));
        session.record_operation();
        assert!(session.updated_at >= before);
    }

    #[test]
    fn session_context_null_value() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("nullable", serde_json::Value::Null);
        assert_eq!(
            session.get_context("nullable"),
            Some(&serde_json::Value::Null)
        );
    }

    #[test]
    fn session_context_empty_key() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("", serde_json::json!("empty_key"));
        assert_eq!(
            session.get_context(""),
            Some(&serde_json::json!("empty_key"))
        );
    }

    #[test]
    fn session_context_numeric_value() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("count", serde_json::json!(42));
        assert_eq!(session.get_context("count"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn session_context_boolean_value() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("flag", serde_json::json!(true));
        assert_eq!(session.get_context("flag"), Some(&serde_json::json!(true)));
    }

    #[test]
    fn session_context_array_value() {
        let mut session = Session::new("Agent", "goal", None);
        let arr = serde_json::json!([1, "two", 3.0, null]);
        session.set_context("list", arr.clone());
        assert_eq!(session.get_context("list"), Some(&arr));
    }

    #[test]
    fn session_context_remove_by_overwrite_null() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("temp", serde_json::json!("data"));
        session.set_context("temp", serde_json::Value::Null);
        assert_eq!(session.get_context("temp"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn session_clone_is_independent() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("k", serde_json::json!("v"));
        let mut cloned = session.clone();
        cloned.set_context("k", serde_json::json!("changed"));
        // Original unchanged
        assert_eq!(session.get_context("k"), Some(&serde_json::json!("v")));
        assert_eq!(cloned.get_context("k"), Some(&serde_json::json!("changed")));
    }

    #[test]
    fn session_debug_contains_agent_name() {
        let session = Session::new("DebugAgent", "debug goal", None);
        let debug = format!("{session:?}");
        assert!(debug.contains("DebugAgent"));
        assert!(debug.contains("debug goal"));
    }

    #[test]
    fn session_serde_preserves_context_order() {
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("z_last", serde_json::json!(1));
        session.set_context("a_first", serde_json::json!(2));
        session.set_context("m_middle", serde_json::json!(3));
        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        // BTreeMap preserves alphabetical order
        let keys: Vec<&String> = restored.context.keys().collect();
        assert_eq!(keys, vec!["a_first", "m_middle", "z_last"]);
    }

    #[test]
    fn session_serde_pretty_output() {
        let session = Session::new("Agent", "goal", None);
        let json = serde_json::to_string_pretty(&session).unwrap();
        assert!(json.contains('\n'));
        assert!(json.contains("agent_name"));
    }

    #[test]
    fn session_multiple_pause_resume_cycles() {
        let mut session = Session::new("Agent", "goal", None);
        for _ in 0..5 {
            session.pause();
            assert_eq!(session.status, SessionStatus::Paused);
            session.resume();
            assert!(session.is_active());
        }
    }

    #[test]
    fn session_double_end() {
        let mut session = Session::new("Agent", "goal", None);
        session.end();
        let first_ended = session.ended_at;
        std::thread::sleep(std::time::Duration::from_millis(2));
        session.end();
        // ended_at gets updated on second end
        assert!(session.ended_at >= first_ended);
        assert_eq!(session.status, SessionStatus::Ended);
    }

    // ── Extended SessionStore tests ───────────────────────────────

    #[test]
    fn store_dir_accessor() {
        let store = SessionStore::new("/tmp/test-session-dir");
        assert_eq!(store.dir(), Path::new("/tmp/test-session-dir"));
    }

    #[test]
    fn store_save_creates_directory() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fwc-mkdir-test-{unique}"));
        let store = SessionStore::new(dir.join("sessions"));
        let session = Session::new("Agent", "goal", None);
        store.save(&session).unwrap();
        assert!(dir.join("sessions").exists());
    }

    #[test]
    fn store_save_and_load_with_context() {
        let store = temp_store();
        let mut session = Session::new("Agent", "goal", None);
        session.set_context("key1", serde_json::json!("value1"));
        session.set_context("key2", serde_json::json!({"nested": true}));
        let id = session.id.clone();
        store.save(&session).unwrap();

        let loaded = store.load(&id).unwrap().unwrap();
        assert_eq!(
            loaded.get_context("key1"),
            Some(&serde_json::json!("value1"))
        );
        assert_eq!(
            loaded.get_context("key2"),
            Some(&serde_json::json!({"nested": true}))
        );
    }

    #[test]
    fn store_save_and_load_preserves_operations() {
        let store = temp_store();
        let mut session = Session::new("Agent", "goal", None);
        session.record_operation();
        session.record_operation();
        session.record_operation();
        let id = session.id.clone();
        store.save(&session).unwrap();

        let loaded = store.load(&id).unwrap().unwrap();
        assert_eq!(loaded.operations_completed, 3);
    }

    #[test]
    fn store_save_and_load_preserves_zone() {
        let store = temp_store();
        let session = Session::new("Agent", "goal", Some("z:prod".into()));
        let id = session.id.clone();
        store.save(&session).unwrap();

        let loaded = store.load(&id).unwrap().unwrap();
        assert_eq!(loaded.zone, Some("z:prod".into()));
    }

    #[test]
    fn store_list_empty_dir_no_filter() {
        let store = temp_store();
        // Create the dir but put no sessions in it
        std::fs::create_dir_all(store.dir()).unwrap();
        let sessions = store.list(None).unwrap();
        assert!(sessions.is_empty());
    }

    #[test]
    fn store_list_ignores_non_json_files() {
        let store = temp_store();
        std::fs::create_dir_all(store.dir()).unwrap();
        // Write a non-JSON file
        std::fs::write(store.dir().join("notes.txt"), "not a session").unwrap();
        let session = Session::new("Agent", "goal", None);
        store.save(&session).unwrap();

        let sessions = store.list(None).unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn store_list_ignores_malformed_json() {
        let store = temp_store();
        std::fs::create_dir_all(store.dir()).unwrap();
        // Write a malformed JSON file
        std::fs::write(store.dir().join("bad.json"), "not valid json {{{").unwrap();
        let session = Session::new("Agent", "goal", None);
        store.save(&session).unwrap();

        let sessions = store.list(None).unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn store_active_session_returns_most_recent() {
        let store = temp_store();
        let s1 = Session::new("Old", "g1", None);
        store.save(&s1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let s2 = Session::new("New", "g2", None);
        store.save(&s2).unwrap();

        let active = store.active_session().unwrap().unwrap();
        // Should return the most recently updated (s2)
        assert_eq!(active.agent_name, "New");
    }

    #[test]
    fn store_load_resolved_with_prefix() {
        let store = temp_store();
        let session = Session::new("Agent", "goal", None);
        let full_id = session.id.as_str().to_string();
        store.save(&session).unwrap();

        let loaded = store.load_resolved(&full_id).unwrap().unwrap();
        assert_eq!(loaded.id, session.id);
    }

    #[test]
    fn store_load_resolved_invalid_returns_none() {
        let store = temp_store();
        // Empty string resolves to None via resolve_session_id
        let loaded = store.load_resolved("").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn store_load_resolved_nonexistent_id() {
        let store = temp_store();
        let loaded = store.load_resolved("nonexist1").unwrap();
        assert!(loaded.is_none());
    }

    // ── Extended resolve_session_id tests ─────────────────────────

    #[test]
    fn resolve_s_colon_only_is_none() {
        assert!(resolve_session_id("s:").is_none());
    }

    #[test]
    fn resolve_single_char_after_prefix() {
        let id = resolve_session_id("s:x").unwrap();
        assert_eq!(id.as_str(), "s:x");
    }

    #[test]
    fn resolve_numeric_id() {
        let id = resolve_session_id("12345678").unwrap();
        assert_eq!(id.as_str(), "s:12345678");
        assert_eq!(id.short_id(), "12345678");
    }

    #[test]
    fn resolve_with_hyphens() {
        let id = resolve_session_id("ab-cd-ef").unwrap();
        assert_eq!(id.short_id(), "ab-cd-ef");
    }

    #[test]
    fn resolve_idempotent_double_prefix() {
        // "s:s:abc" should parse: starts with "s:", len > 2 => Some
        let id = resolve_session_id("s:s:abc").unwrap();
        assert_eq!(id.as_str(), "s:s:abc");
    }

    // ── session_dir additional tests ──────────────────────────────

    #[test]
    fn session_dir_with_nested_base() {
        let base = Path::new("/opt/data/fwc");
        let dir = session_dir(base);
        assert_eq!(dir, PathBuf::from("/opt/data/fwc/sessions"));
    }

    #[test]
    fn session_dir_with_trailing_slash_base() {
        let base = Path::new("/home/user/.fwc/");
        let dir = session_dir(base);
        assert_eq!(dir, PathBuf::from("/home/user/.fwc/sessions"));
    }

    // ── Serde edge cases ──────────────────────────────────────────

    #[test]
    fn session_serde_empty_context() {
        let session = Session::new("Agent", "goal", None);
        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert!(restored.context.is_empty());
    }

    #[test]
    fn session_serde_no_zone() {
        let session = Session::new("Agent", "goal", None);
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("\"zone\":null"));
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert!(restored.zone.is_none());
    }

    #[test]
    fn session_serde_with_zone() {
        let session = Session::new("Agent", "goal", Some("z:staging".into()));
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("z:staging"));
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.zone, Some("z:staging".into()));
    }

    #[test]
    fn session_serde_status_snake_case() {
        // Verify that serde uses snake_case for status
        let session = Session::new("Agent", "goal", None);
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("\"active\""));
    }

    #[test]
    fn session_id_parse_numeric() {
        let id = SessionId::parse("s:00000001").unwrap();
        assert_eq!(id.short_id(), "00000001");
    }
}
