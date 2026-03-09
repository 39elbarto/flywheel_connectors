//! Operation-level advisory locks for multi-agent conflict prevention.
//!
//! Enables multiple agents to coordinate access to connector operations by
//! acquiring named locks with TTL-based expiry. Locks are file-backed in
//! `~/.fwc/locks/` and automatically expire after their TTL elapses.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ── Types ──────────────────────────────────────────────────────────

/// A named advisory lock on a connector operation scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpLock {
    /// The resource being locked (e.g. `"github.issues"`, `"slack.channels"`).
    pub resource: String,
    /// Agent that holds the lock.
    pub agent: String,
    /// When the lock was acquired.
    pub acquired_at: DateTime<Utc>,
    /// When the lock expires (auto-release).
    pub expires_at: DateTime<Utc>,
    /// Optional reason for acquiring the lock.
    pub reason: Option<String>,
}

impl OpLock {
    /// Whether this lock has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Whether this lock is still active (not expired).
    pub fn is_active(&self) -> bool {
        !self.is_expired()
    }

    /// Remaining time until expiry. Returns zero duration if already expired.
    pub fn remaining(&self) -> Duration {
        let now = Utc::now();
        if now >= self.expires_at {
            Duration::zero()
        } else {
            self.expires_at - now
        }
    }

    /// Human-readable remaining time.
    pub fn remaining_display(&self) -> String {
        let remaining = self.remaining();
        if remaining.is_zero() {
            return "expired".to_string();
        }
        let total_secs = remaining.num_seconds();
        if total_secs < 60 {
            format!("{total_secs}s")
        } else if total_secs < 3600 {
            format!("{}m {}s", total_secs / 60, total_secs % 60)
        } else {
            format!("{}h {}m", total_secs / 3600, (total_secs % 3600) / 60)
        }
    }
}

/// Result of attempting to acquire a lock.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AcquireResult {
    /// Lock acquired successfully.
    Acquired { lock: OpLock },
    /// Resource is already locked by another agent.
    Conflict {
        held_by: String,
        expires_at: String,
        remaining: String,
    },
}

impl AcquireResult {
    /// Whether the lock was successfully acquired.
    pub const fn is_acquired(&self) -> bool {
        matches!(self, Self::Acquired { .. })
    }
}

/// Result of a lock check.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CheckResult {
    /// Resource is not locked.
    Free,
    /// Locked by this agent.
    HeldBySelf { lock: OpLock },
    /// Locked by another agent.
    HeldByOther {
        held_by: String,
        expires_at: String,
        remaining: String,
    },
}

// ── Lock Store ─────────────────────────────────────────────────────

/// File-backed lock store in `~/.fwc/locks/`.
pub struct LockStore {
    dir: PathBuf,
}

/// The inner data structure persisted to disk.
#[derive(Default, Serialize, Deserialize)]
struct LockData {
    locks: BTreeMap<String, OpLock>,
}

impl LockStore {
    /// Create a store at the default location.
    pub fn default_path() -> Self {
        let home = std::env::var("HOME").map_or_else(|_| PathBuf::from("."), PathBuf::from);
        Self {
            dir: home.join(".fwc").join("locks"),
        }
    }

    /// Create a store at a custom path (for testing).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Attempt to acquire a lock on a resource.
    ///
    /// If the resource is already locked by another agent and the lock hasn't
    /// expired, returns `Conflict`. If locked by the same agent, refreshes the
    /// lock (extends TTL).
    pub fn acquire(
        &self,
        resource: &str,
        agent: &str,
        ttl_minutes: u32,
        reason: Option<String>,
    ) -> Result<AcquireResult, String> {
        let mut data = self.load_data()?;
        Self::gc_expired(&mut data);

        if let Some(existing) = data.locks.get(resource) {
            if existing.agent != agent {
                // Locked by another agent.
                return Ok(AcquireResult::Conflict {
                    held_by: existing.agent.clone(),
                    expires_at: existing.expires_at.to_rfc3339(),
                    remaining: existing.remaining_display(),
                });
            }
            // Same agent — refresh the lock.
        }

        let now = Utc::now();
        let lock = OpLock {
            resource: resource.to_owned(),
            agent: agent.to_owned(),
            acquired_at: now,
            expires_at: now + Duration::minutes(i64::from(ttl_minutes)),
            reason,
        };
        data.locks.insert(resource.to_owned(), lock.clone());
        self.save_data(&data)?;

        Ok(AcquireResult::Acquired { lock })
    }

    /// Release a lock. Only the holding agent can release it.
    ///
    /// Returns `true` if the lock was released, `false` if it didn't exist
    /// or was held by a different agent.
    pub fn release(&self, resource: &str, agent: &str) -> Result<bool, String> {
        let mut data = self.load_data()?;
        Self::gc_expired(&mut data);

        if let Some(existing) = data.locks.get(resource) {
            if existing.agent != agent {
                return Ok(false); // Can't release another agent's lock.
            }
        } else {
            return Ok(false); // No lock to release.
        }

        data.locks.remove(resource);
        self.save_data(&data)?;
        Ok(true)
    }

    /// Check the lock status of a resource.
    pub fn check(&self, resource: &str, agent: &str) -> Result<CheckResult, String> {
        let mut data = self.load_data()?;
        Self::gc_expired(&mut data);

        match data.locks.get(resource) {
            None => Ok(CheckResult::Free),
            Some(lock) if lock.agent == agent => Ok(CheckResult::HeldBySelf { lock: lock.clone() }),
            Some(lock) => Ok(CheckResult::HeldByOther {
                held_by: lock.agent.clone(),
                expires_at: lock.expires_at.to_rfc3339(),
                remaining: lock.remaining_display(),
            }),
        }
    }

    /// List all active (non-expired) locks.
    pub fn list(&self) -> Result<Vec<OpLock>, String> {
        let mut data = self.load_data()?;
        Self::gc_expired(&mut data);
        Ok(data.locks.values().cloned().collect())
    }

    /// List all locks held by a specific agent.
    pub fn list_by_agent(&self, agent: &str) -> Result<Vec<OpLock>, String> {
        let locks = self.list()?;
        Ok(locks.into_iter().filter(|l| l.agent == agent).collect())
    }

    /// Release all locks held by a specific agent.
    pub fn release_all(&self, agent: &str) -> Result<usize, String> {
        let mut data = self.load_data()?;
        Self::gc_expired(&mut data);

        let resources: Vec<String> = data
            .locks
            .iter()
            .filter(|(_, lock)| lock.agent == agent)
            .map(|(key, _)| key.clone())
            .collect();

        let count = resources.len();
        for resource in &resources {
            data.locks.remove(resource);
        }

        if count > 0 {
            self.save_data(&data)?;
        }
        Ok(count)
    }

    /// Count active locks.
    pub fn count(&self) -> Result<usize, String> {
        let mut data = self.load_data()?;
        Self::gc_expired(&mut data);
        Ok(data.locks.len())
    }

    /// The directory where lock data is stored.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    // ── Internal ───────────────────────────────────────────────────

    fn load_data(&self) -> Result<LockData, String> {
        let path = self.data_path();
        if !path.exists() {
            return Ok(LockData::default());
        }
        let json = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read lock store: {e}"))?;
        serde_json::from_str(&json).map_err(|e| format!("lock store corrupted: {e}"))
    }

    fn save_data(&self, data: &LockData) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("failed to create lock directory: {e}"))?;
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| format!("failed to serialize locks: {e}"))?;
        std::fs::write(self.data_path(), json)
            .map_err(|e| format!("failed to write lock store: {e}"))
    }

    fn data_path(&self) -> PathBuf {
        self.dir.join("locks.json")
    }

    /// Remove expired locks from the data structure.
    fn gc_expired(data: &mut LockData) {
        data.locks.retain(|_, lock| lock.is_active());
    }
}

/// Parse a TTL string like `"30m"`, `"2h"`, `"90s"` into minutes.
pub fn parse_ttl(input: &str) -> Result<u32, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("TTL cannot be empty".to_string());
    }

    // Try suffixed format.
    if let Some(num) = input.strip_suffix('m') {
        return num
            .parse::<u32>()
            .map_err(|_| format!("invalid TTL minutes: `{num}`"));
    }
    if let Some(num) = input.strip_suffix('h') {
        return num
            .parse::<u32>()
            .map(|h| h * 60)
            .map_err(|_| format!("invalid TTL hours: `{num}`"));
    }
    if let Some(num) = input.strip_suffix('s') {
        return num
            .parse::<u32>()
            .map(|s| s.div_ceil(60)) // Round up to next minute.
            .map_err(|_| format!("invalid TTL seconds: `{num}`"));
    }

    // Plain number defaults to minutes.
    input.parse::<u32>().map_err(|_| {
        format!("invalid TTL: `{input}`; expected number with optional suffix (30m, 2h, 90s)")
    })
}

/// Validate a resource identifier.
pub fn validate_resource(resource: &str) -> Result<(), String> {
    if resource.is_empty() {
        return Err("resource identifier cannot be empty".to_string());
    }
    if resource.len() > 128 {
        return Err("resource identifier too long (max 128 characters)".to_string());
    }
    if !resource
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '*')
    {
        return Err(format!(
            "resource `{resource}` contains invalid characters; use alphanumeric, dash, underscore, dot, or wildcard"
        ));
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> LockStore {
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fwc-lock-test-{unique}"));
        LockStore::new(dir)
    }

    // ── OpLock ────────────────────────────────────────────────────

    #[test]
    fn lock_not_expired_when_future() {
        let lock = OpLock {
            resource: "github.issues".to_owned(),
            agent: "SunnyMoose".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(30),
            reason: None,
        };
        assert!(lock.is_active());
        assert!(!lock.is_expired());
    }

    #[test]
    fn lock_expired_when_past() {
        let lock = OpLock {
            resource: "github.issues".to_owned(),
            agent: "SunnyMoose".to_owned(),
            acquired_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::hours(1),
            reason: None,
        };
        assert!(lock.is_expired());
        assert!(!lock.is_active());
    }

    #[test]
    fn remaining_positive_for_active_lock() {
        let lock = OpLock {
            resource: "test".to_owned(),
            agent: "Agent".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(10),
            reason: None,
        };
        let remaining = lock.remaining();
        assert!(remaining.num_seconds() > 0);
    }

    #[test]
    fn remaining_zero_for_expired_lock() {
        let lock = OpLock {
            resource: "test".to_owned(),
            agent: "Agent".to_owned(),
            acquired_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::hours(1),
            reason: None,
        };
        assert!(lock.remaining().is_zero());
    }

    #[test]
    fn remaining_display_expired() {
        let lock = OpLock {
            resource: "test".to_owned(),
            agent: "Agent".to_owned(),
            acquired_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::hours(1),
            reason: None,
        };
        assert_eq!(lock.remaining_display(), "expired");
    }

    #[test]
    fn remaining_display_seconds() {
        let lock = OpLock {
            resource: "test".to_owned(),
            agent: "Agent".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(45),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.ends_with('s'));
        assert!(!display.contains('m'));
    }

    #[test]
    fn remaining_display_minutes() {
        let lock = OpLock {
            resource: "test".to_owned(),
            agent: "Agent".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5) + Duration::seconds(30),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.contains('m'));
    }

    #[test]
    fn remaining_display_hours() {
        let lock = OpLock {
            resource: "test".to_owned(),
            agent: "Agent".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(2) + Duration::minutes(15),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.contains('h'));
    }

    #[test]
    fn lock_serde_roundtrip() {
        let lock = OpLock {
            resource: "github.issues".to_owned(),
            agent: "SunnyMoose".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(30),
            reason: Some("batch operation".to_owned()),
        };
        let json = serde_json::to_string(&lock).unwrap();
        let restored: OpLock = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.resource, "github.issues");
        assert_eq!(restored.agent, "SunnyMoose");
        assert_eq!(restored.reason.as_deref(), Some("batch operation"));
    }

    // ── AcquireResult ─────────────────────────────────────────────

    #[test]
    fn acquire_result_is_acquired() {
        let result = AcquireResult::Acquired {
            lock: OpLock {
                resource: "test".to_owned(),
                agent: "Agent".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(10),
                reason: None,
            },
        };
        assert!(result.is_acquired());
    }

    #[test]
    fn acquire_result_conflict_is_not_acquired() {
        let result = AcquireResult::Conflict {
            held_by: "Other".to_owned(),
            expires_at: Utc::now().to_rfc3339(),
            remaining: "5m".to_owned(),
        };
        assert!(!result.is_acquired());
    }

    // ── LockStore: acquire ────────────────────────────────────────

    #[test]
    fn acquire_new_lock() {
        let store = temp_store();
        let result = store
            .acquire("github.issues", "SunnyMoose", 30, None)
            .unwrap();
        assert!(result.is_acquired());

        if let AcquireResult::Acquired { lock } = result {
            assert_eq!(lock.resource, "github.issues");
            assert_eq!(lock.agent, "SunnyMoose");
            assert!(lock.is_active());
        }
    }

    #[test]
    fn acquire_conflict_different_agent() {
        let store = temp_store();
        store.acquire("github.issues", "AgentA", 30, None).unwrap();
        let result = store.acquire("github.issues", "AgentB", 30, None).unwrap();
        assert!(!result.is_acquired());

        if let AcquireResult::Conflict { held_by, .. } = result {
            assert_eq!(held_by, "AgentA");
        }
    }

    #[test]
    fn acquire_same_agent_refreshes() {
        let store = temp_store();
        store
            .acquire("github.issues", "SunnyMoose", 10, None)
            .unwrap();
        let result = store
            .acquire(
                "github.issues",
                "SunnyMoose",
                60,
                Some("extended".to_owned()),
            )
            .unwrap();
        assert!(result.is_acquired());

        if let AcquireResult::Acquired { lock } = result {
            assert_eq!(lock.reason.as_deref(), Some("extended"));
        }
    }

    #[test]
    fn acquire_different_resources() {
        let store = temp_store();
        let r1 = store.acquire("github.issues", "AgentA", 30, None).unwrap();
        let r2 = store.acquire("slack.channels", "AgentB", 30, None).unwrap();
        assert!(r1.is_acquired());
        assert!(r2.is_acquired());
    }

    // ── LockStore: release ────────────────────────────────────────

    #[test]
    fn release_own_lock() {
        let store = temp_store();
        store
            .acquire("github.issues", "SunnyMoose", 30, None)
            .unwrap();
        assert!(store.release("github.issues", "SunnyMoose").unwrap());
    }

    #[test]
    fn release_nonexistent() {
        let store = temp_store();
        assert!(!store.release("nope", "SunnyMoose").unwrap());
    }

    #[test]
    fn release_other_agents_lock_fails() {
        let store = temp_store();
        store.acquire("github.issues", "AgentA", 30, None).unwrap();
        assert!(!store.release("github.issues", "AgentB").unwrap());
        // Lock should still be held by AgentA.
        let check = store.check("github.issues", "AgentA").unwrap();
        assert!(matches!(check, CheckResult::HeldBySelf { .. }));
    }

    // ── LockStore: check ──────────────────────────────────────────

    #[test]
    fn check_free_resource() {
        let store = temp_store();
        let result = store.check("github.issues", "SunnyMoose").unwrap();
        assert!(matches!(result, CheckResult::Free));
    }

    #[test]
    fn check_held_by_self() {
        let store = temp_store();
        store
            .acquire("github.issues", "SunnyMoose", 30, None)
            .unwrap();
        let result = store.check("github.issues", "SunnyMoose").unwrap();
        assert!(matches!(result, CheckResult::HeldBySelf { .. }));
    }

    #[test]
    fn check_held_by_other() {
        let store = temp_store();
        store.acquire("github.issues", "AgentA", 30, None).unwrap();
        let result = store.check("github.issues", "AgentB").unwrap();
        assert!(matches!(result, CheckResult::HeldByOther { .. }));
    }

    // ── LockStore: list ───────────────────────────────────────────

    #[test]
    fn list_empty_store() {
        let store = temp_store();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn list_all_locks() {
        let store = temp_store();
        store.acquire("github.issues", "AgentA", 30, None).unwrap();
        store.acquire("slack.channels", "AgentB", 30, None).unwrap();
        let locks = store.list().unwrap();
        assert_eq!(locks.len(), 2);
    }

    #[test]
    fn list_by_agent() {
        let store = temp_store();
        store.acquire("github.issues", "AgentA", 30, None).unwrap();
        store.acquire("slack.channels", "AgentA", 30, None).unwrap();
        store.acquire("twilio.sms", "AgentB", 30, None).unwrap();

        let a_locks = store.list_by_agent("AgentA").unwrap();
        assert_eq!(a_locks.len(), 2);

        let b_locks = store.list_by_agent("AgentB").unwrap();
        assert_eq!(b_locks.len(), 1);
    }

    // ── LockStore: release_all ────────────────────────────────────

    #[test]
    fn release_all_by_agent() {
        let store = temp_store();
        store.acquire("github.issues", "AgentA", 30, None).unwrap();
        store.acquire("slack.channels", "AgentA", 30, None).unwrap();
        store.acquire("twilio.sms", "AgentB", 30, None).unwrap();

        let released = store.release_all("AgentA").unwrap();
        assert_eq!(released, 2);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn release_all_none_held() {
        let store = temp_store();
        store.acquire("github.issues", "AgentA", 30, None).unwrap();
        let released = store.release_all("AgentB").unwrap();
        assert_eq!(released, 0);
    }

    // ── LockStore: count ──────────────────────────────────────────

    #[test]
    fn count_locks() {
        let store = temp_store();
        assert_eq!(store.count().unwrap(), 0);
        store.acquire("github.issues", "AgentA", 30, None).unwrap();
        assert_eq!(store.count().unwrap(), 1);
        store.acquire("slack.channels", "AgentB", 30, None).unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    // ── TTL expiry ────────────────────────────────────────────────

    #[test]
    fn expired_lock_is_garbage_collected() {
        let store = temp_store();

        // Manually write an expired lock.
        let mut data = LockData::default();
        data.locks.insert(
            "old.resource".to_owned(),
            OpLock {
                resource: "old.resource".to_owned(),
                agent: "Ghost".to_owned(),
                acquired_at: Utc::now() - Duration::hours(3),
                expires_at: Utc::now() - Duration::hours(1),
                reason: None,
            },
        );
        std::fs::create_dir_all(store.dir()).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(store.data_path(), json).unwrap();

        // After any operation, expired locks are GC'd.
        let locks = store.list().unwrap();
        assert!(locks.is_empty());
    }

    #[test]
    fn expired_lock_allows_new_acquisition() {
        let store = temp_store();

        // Manually write an expired lock.
        let mut data = LockData::default();
        data.locks.insert(
            "github.issues".to_owned(),
            OpLock {
                resource: "github.issues".to_owned(),
                agent: "OldAgent".to_owned(),
                acquired_at: Utc::now() - Duration::hours(2),
                expires_at: Utc::now() - Duration::seconds(1),
                reason: None,
            },
        );
        std::fs::create_dir_all(store.dir()).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(store.data_path(), json).unwrap();

        // New agent should be able to acquire it.
        let result = store
            .acquire("github.issues", "NewAgent", 30, None)
            .unwrap();
        assert!(result.is_acquired());
    }

    // ── parse_ttl ─────────────────────────────────────────────────

    #[test]
    fn parse_ttl_minutes() {
        assert_eq!(parse_ttl("30m").unwrap(), 30);
    }

    #[test]
    fn parse_ttl_hours() {
        assert_eq!(parse_ttl("2h").unwrap(), 120);
    }

    #[test]
    fn parse_ttl_seconds() {
        assert_eq!(parse_ttl("90s").unwrap(), 2); // Rounds up to 2 minutes.
        assert_eq!(parse_ttl("60s").unwrap(), 1);
    }

    #[test]
    fn parse_ttl_plain_number() {
        assert_eq!(parse_ttl("45").unwrap(), 45);
    }

    #[test]
    fn parse_ttl_trims_whitespace() {
        assert_eq!(parse_ttl("  30m  ").unwrap(), 30);
    }

    #[test]
    fn parse_ttl_empty() {
        assert!(parse_ttl("").is_err());
    }

    #[test]
    fn parse_ttl_invalid() {
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("30x").is_err());
    }

    // ── validate_resource ─────────────────────────────────────────

    #[test]
    fn validate_resource_valid() {
        assert!(validate_resource("github.issues").is_ok());
        assert!(validate_resource("slack.channels").is_ok());
        assert!(validate_resource("github.*").is_ok());
        assert!(validate_resource("twilio-sms").is_ok());
        assert!(validate_resource("under_score").is_ok());
    }

    #[test]
    fn validate_resource_empty() {
        assert!(validate_resource("").is_err());
    }

    #[test]
    fn validate_resource_too_long() {
        let long = "a".repeat(129);
        assert!(validate_resource(&long).is_err());
    }

    #[test]
    fn validate_resource_invalid_chars() {
        assert!(validate_resource("has space").is_err());
        assert!(validate_resource("has/slash").is_err());
        assert!(validate_resource("has@at").is_err());
    }

    #[test]
    fn validate_resource_max_length_ok() {
        let max = "a".repeat(128);
        assert!(validate_resource(&max).is_ok());
    }

    // ── CheckResult variants ──────────────────────────────────────

    #[test]
    fn check_result_serializes() {
        let free = CheckResult::Free;
        let json = serde_json::to_value(&free).unwrap();
        assert_eq!(json["status"], "free");

        let held = CheckResult::HeldByOther {
            held_by: "Agent".to_owned(),
            expires_at: "2026-03-09T12:00:00Z".to_owned(),
            remaining: "5m".to_owned(),
        };
        let json = serde_json::to_value(&held).unwrap();
        assert_eq!(json["status"], "held_by_other");
        assert_eq!(json["held_by"], "Agent");
    }

    // ── OpLock additional ────────────────────────────────────────

    #[test]
    fn lock_with_reason() {
        let lock = OpLock {
            resource: "slack.channels".to_owned(),
            agent: "TestAgent".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(15),
            reason: Some("batch import".to_owned()),
        };
        assert_eq!(lock.reason.as_deref(), Some("batch import"));
    }

    #[test]
    fn lock_without_reason() {
        let lock = OpLock {
            resource: "test".to_owned(),
            agent: "A".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            reason: None,
        };
        assert!(lock.reason.is_none());
    }

    #[test]
    fn lock_clone() {
        let lock = OpLock {
            resource: "github.issues".to_owned(),
            agent: "SunnyMoose".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(30),
            reason: Some("test".to_owned()),
        };
        let cloned = lock.clone();
        assert_eq!(cloned.resource, lock.resource);
        assert_eq!(cloned.agent, lock.agent);
        assert_eq!(cloned.reason, lock.reason);
    }

    #[test]
    fn lock_debug_format() {
        let lock = OpLock {
            resource: "test.res".to_owned(),
            agent: "Agent1".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            reason: None,
        };
        let debug = format!("{lock:?}");
        assert!(debug.contains("OpLock"));
        assert!(debug.contains("test.res"));
    }

    #[test]
    fn lock_serde_roundtrip_no_reason() {
        let lock = OpLock {
            resource: "github.prs".to_owned(),
            agent: "Agent".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(10),
            reason: None,
        };
        let json = serde_json::to_string(&lock).unwrap();
        let restored: OpLock = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.resource, "github.prs");
        assert!(restored.reason.is_none());
    }

    #[test]
    fn remaining_display_exactly_60_seconds() {
        let lock = OpLock {
            resource: "test".to_owned(),
            agent: "Agent".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(61),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.contains('m'));
    }

    #[test]
    fn remaining_display_exactly_3600_seconds() {
        let lock = OpLock {
            resource: "test".to_owned(),
            agent: "Agent".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(3601),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.contains('h'));
    }

    // ── AcquireResult additional ─────────────────────────────────

    #[test]
    fn acquire_result_acquired_serializes() {
        let result = AcquireResult::Acquired {
            lock: OpLock {
                resource: "slack.messages".to_owned(),
                agent: "TestAgent".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(5),
                reason: None,
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "acquired");
        assert_eq!(json["lock"]["resource"], "slack.messages");
    }

    #[test]
    fn acquire_result_conflict_serializes() {
        let result = AcquireResult::Conflict {
            held_by: "AgentX".to_owned(),
            expires_at: "2026-03-09T14:00:00Z".to_owned(),
            remaining: "10m 30s".to_owned(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "conflict");
        assert_eq!(json["held_by"], "AgentX");
    }

    #[test]
    fn acquire_result_clone() {
        let result = AcquireResult::Conflict {
            held_by: "X".to_owned(),
            expires_at: "t".to_owned(),
            remaining: "5m".to_owned(),
        };
        let cloned = result.clone();
        assert!(!result.is_acquired());
        let _ = cloned;
    }

    // ── CheckResult additional ───────────────────────────────────

    #[test]
    fn check_result_held_by_self_serializes() {
        let result = CheckResult::HeldBySelf {
            lock: OpLock {
                resource: "test.resource".to_owned(),
                agent: "MyAgent".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(20),
                reason: Some("testing".to_owned()),
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "held_by_self");
        assert_eq!(json["lock"]["agent"], "MyAgent");
    }

    #[test]
    fn check_result_clone() {
        let result = CheckResult::Free;
        let cloned = result.clone();
        let json = serde_json::to_value(&result).unwrap();
        let _ = cloned;
        assert_eq!(json["status"], "free");
    }

    // ── LockStore: acquire additional ────────────────────────────

    #[test]
    fn acquire_with_reason() {
        let store = temp_store();
        let result = store
            .acquire(
                "github.issues",
                "SunnyMoose",
                30,
                Some("batch import".to_owned()),
            )
            .unwrap();
        if let AcquireResult::Acquired { lock } = result {
            assert_eq!(lock.reason.as_deref(), Some("batch import"));
        } else {
            panic!("expected Acquired");
        }
    }

    #[test]
    fn acquire_multiple_resources_same_agent() {
        let store = temp_store();
        store.acquire("res.a", "Agent1", 30, None).unwrap();
        store.acquire("res.b", "Agent1", 30, None).unwrap();
        store.acquire("res.c", "Agent1", 30, None).unwrap();
        assert_eq!(store.count().unwrap(), 3);
        let agent_locks = store.list_by_agent("Agent1").unwrap();
        assert_eq!(agent_locks.len(), 3);
    }

    #[test]
    fn acquire_many_agents_different_resources() {
        let store = temp_store();
        for i in 0..5 {
            let resource = format!("resource.{i}");
            let agent = format!("Agent{i}");
            let result = store.acquire(&resource, &agent, 30, None).unwrap();
            assert!(result.is_acquired());
        }
        assert_eq!(store.count().unwrap(), 5);
    }

    // ── LockStore: release additional ────────────────────────────

    #[test]
    fn release_then_reacquire() {
        let store = temp_store();
        store.acquire("res", "AgentA", 30, None).unwrap();
        store.release("res", "AgentA").unwrap();
        let result = store.acquire("res", "AgentB", 30, None).unwrap();
        assert!(result.is_acquired());
    }

    #[test]
    fn release_one_keeps_others() {
        let store = temp_store();
        store.acquire("res.a", "Agent", 30, None).unwrap();
        store.acquire("res.b", "Agent", 30, None).unwrap();
        store.release("res.a", "Agent").unwrap();
        assert_eq!(store.count().unwrap(), 1);
        let check = store.check("res.b", "Agent").unwrap();
        assert!(matches!(check, CheckResult::HeldBySelf { .. }));
    }

    // ── LockStore: check additional ──────────────────────────────

    #[test]
    fn check_after_release_is_free() {
        let store = temp_store();
        store.acquire("res", "Agent", 30, None).unwrap();
        store.release("res", "Agent").unwrap();
        let result = store.check("res", "Agent").unwrap();
        assert!(matches!(result, CheckResult::Free));
    }

    #[test]
    fn check_held_by_other_contains_info() {
        let store = temp_store();
        store.acquire("res", "AgentA", 30, None).unwrap();
        let result = store.check("res", "AgentB").unwrap();
        match result {
            CheckResult::HeldByOther {
                held_by,
                expires_at,
                remaining,
            } => {
                assert_eq!(held_by, "AgentA");
                assert!(!expires_at.is_empty());
                assert!(!remaining.is_empty());
            }
            other => panic!("expected HeldByOther, got {other:?}"),
        }
    }

    // ── LockStore: list additional ───────────────────────────────

    #[test]
    fn list_by_agent_no_matches() {
        let store = temp_store();
        store.acquire("res", "AgentA", 30, None).unwrap();
        let locks = store.list_by_agent("AgentB").unwrap();
        assert!(locks.is_empty());
    }

    #[test]
    fn list_returns_resources_in_order() {
        let store = temp_store();
        store.acquire("b.res", "Agent", 30, None).unwrap();
        store.acquire("a.res", "Agent", 30, None).unwrap();
        let locks = store.list().unwrap();
        assert_eq!(locks.len(), 2);
        // BTreeMap stores in sorted order
        assert_eq!(locks[0].resource, "a.res");
        assert_eq!(locks[1].resource, "b.res");
    }

    // ── LockStore: release_all additional ────────────────────────

    #[test]
    fn release_all_preserves_other_agents() {
        let store = temp_store();
        store.acquire("res.a", "AgentA", 30, None).unwrap();
        store.acquire("res.b", "AgentB", 30, None).unwrap();
        store.acquire("res.c", "AgentA", 30, None).unwrap();
        store.release_all("AgentA").unwrap();
        assert_eq!(store.count().unwrap(), 1);
        let check = store.check("res.b", "AgentB").unwrap();
        assert!(matches!(check, CheckResult::HeldBySelf { .. }));
    }

    // ── LockStore: dir ──────────────────────────────────────────

    #[test]
    fn store_dir_accessible() {
        let store = temp_store();
        let dir = store.dir();
        assert!(dir.to_str().unwrap().contains("fwc-lock-test"));
    }

    #[test]
    fn default_path_store() {
        let store = LockStore::default_path();
        let dir = store.dir();
        assert!(dir.to_str().unwrap().contains("locks"));
    }

    // ── parse_ttl additional ─────────────────────────────────────

    #[test]
    fn parse_ttl_one_minute() {
        assert_eq!(parse_ttl("1m").unwrap(), 1);
    }

    #[test]
    fn parse_ttl_one_hour() {
        assert_eq!(parse_ttl("1h").unwrap(), 60);
    }

    #[test]
    fn parse_ttl_seconds_round_up() {
        assert_eq!(parse_ttl("30s").unwrap(), 1); // 30s rounds up to 1 min
        assert_eq!(parse_ttl("61s").unwrap(), 2); // 61s rounds up to 2 min
        assert_eq!(parse_ttl("120s").unwrap(), 2); // 120s = exactly 2 min
        assert_eq!(parse_ttl("1s").unwrap(), 1); // 1s rounds up to 1 min
    }

    #[test]
    fn parse_ttl_large_value() {
        assert_eq!(parse_ttl("24h").unwrap(), 1440);
    }

    #[test]
    fn parse_ttl_whitespace_only_is_error() {
        assert!(parse_ttl("   ").is_err());
    }

    #[test]
    fn parse_ttl_invalid_suffix() {
        assert!(parse_ttl("10x").is_err());
    }

    #[test]
    fn parse_ttl_negative_is_error() {
        assert!(parse_ttl("-5m").is_err());
    }

    // ── validate_resource additional ─────────────────────────────

    #[test]
    fn validate_resource_with_dots_and_wildcards() {
        assert!(validate_resource("github.*").is_ok());
        assert!(validate_resource("a.b.c.d").is_ok());
        assert!(validate_resource("*").is_ok());
    }

    #[test]
    fn validate_resource_with_dashes_and_underscores() {
        assert!(validate_resource("my-connector_v2").is_ok());
    }

    #[test]
    fn validate_resource_just_at_max_length() {
        let exactly_128 = "a".repeat(128);
        assert!(validate_resource(&exactly_128).is_ok());
        let over_128 = "a".repeat(129);
        assert!(validate_resource(&over_128).is_err());
    }

    #[test]
    fn validate_resource_special_chars() {
        assert!(validate_resource("test!").is_err());
        assert!(validate_resource("a b").is_err());
        assert!(validate_resource("a\tb").is_err());
        assert!(validate_resource("a\nb").is_err());
        assert!(validate_resource("foo#bar").is_err());
        assert!(validate_resource("$env").is_err());
    }

    #[test]
    fn validate_resource_purely_numeric() {
        assert!(validate_resource("12345").is_ok());
    }

    #[test]
    fn validate_resource_single_char() {
        assert!(validate_resource("a").is_ok());
        assert!(validate_resource("-").is_ok());
        assert!(validate_resource("_").is_ok());
        assert!(validate_resource(".").is_ok());
    }
}
