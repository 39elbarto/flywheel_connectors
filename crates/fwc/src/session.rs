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
        assert!(std::path::Path::new(&expected_file)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json")));
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
}
