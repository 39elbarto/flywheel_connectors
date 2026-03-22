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

        let path = self.data_path();
        let temp_path = Self::temp_path_for(&path);

        let write_result = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;

            #[cfg(not(windows))]
            std::fs::rename(&temp_path, &path)?;

            #[cfg(windows)]
            {
                if path.exists() {
                    std::fs::remove_file(&path)?;
                }
                std::fs::rename(&temp_path, &path)?;
            }
            Ok(())
        })();

        if write_result.is_err() && temp_path.exists() {
            let _ = std::fs::remove_file(&temp_path);
        }

        write_result.map_err(|e| format!("failed to safely write lock store: {e}"))
    }

    fn data_path(&self) -> PathBuf {
        self.dir.join("locks.json")
    }

    fn temp_path_for(path: &Path) -> PathBuf {
        path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4().simple()))
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
        let dir = std::env::temp_dir().join(format!("fwc-lock-test-{}", uuid::Uuid::new_v4()));
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

    #[test]
    fn lock_store_temp_path_is_unique() {
        let store = temp_store();
        let path = store.data_path();
        let first = LockStore::temp_path_for(&path);
        let second = LockStore::temp_path_for(&path);

        assert_ne!(first, second);
        assert!(first.to_string_lossy().contains(".tmp."));
        assert!(second.to_string_lossy().contains(".tmp."));
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

    // ── OpLock: remaining_display boundary ──────────────────────

    #[test]
    fn remaining_display_one_second() {
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(2),
            reason: None,
        };
        let display = lock.remaining_display();
        // Should be in seconds range, not minutes
        assert!(display.ends_with('s'));
        assert!(!display.contains('m'));
        assert!(!display.contains('h'));
    }

    #[test]
    fn remaining_display_exactly_one_minute() {
        // 60 seconds exactly should format as minutes
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(60) + Duration::milliseconds(500),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.contains('m'));
    }

    #[test]
    fn remaining_display_59_seconds() {
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(59) + Duration::milliseconds(500),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.ends_with('s'));
        assert!(!display.contains('m'));
    }

    #[test]
    fn remaining_display_3599_seconds() {
        // Just under one hour: should show minutes
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(3599) + Duration::milliseconds(500),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.contains('m'));
        assert!(!display.contains('h'));
    }

    #[test]
    fn remaining_display_exactly_one_hour() {
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(3600) + Duration::milliseconds(500),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.contains('h'));
    }

    #[test]
    fn remaining_display_multiple_hours() {
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(5) + Duration::minutes(45),
            reason: None,
        };
        let display = lock.remaining_display();
        assert!(display.contains('h'));
        assert!(display.contains('m'));
    }

    // ── OpLock: serialization edge cases ────────────────────────

    #[test]
    fn lock_serde_preserves_timestamps() {
        let now = Utc::now();
        let lock = OpLock {
            resource: "ts.test".to_owned(),
            agent: "Ag".to_owned(),
            acquired_at: now,
            expires_at: now + Duration::minutes(10),
            reason: None,
        };
        let json = serde_json::to_string(&lock).unwrap();
        let restored: OpLock = serde_json::from_str(&json).unwrap();
        // Timestamps should round-trip (chrono serializes to RFC3339)
        assert_eq!(
            restored.acquired_at.timestamp(),
            lock.acquired_at.timestamp()
        );
        assert_eq!(restored.expires_at.timestamp(), lock.expires_at.timestamp());
    }

    #[test]
    fn lock_serde_json_contains_all_fields() {
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(1),
            reason: Some("why".to_owned()),
        };
        let val = serde_json::to_value(&lock).unwrap();
        assert!(val.get("resource").is_some());
        assert!(val.get("agent").is_some());
        assert!(val.get("acquired_at").is_some());
        assert!(val.get("expires_at").is_some());
        assert!(val.get("reason").is_some());
        assert_eq!(val["reason"], "why");
    }

    #[test]
    fn lock_serde_null_reason_in_json() {
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(1),
            reason: None,
        };
        let val = serde_json::to_value(&lock).unwrap();
        assert!(val["reason"].is_null());
    }

    #[test]
    fn lock_deserialize_from_known_json() {
        let json = r#"{
            "resource": "github.issues",
            "agent": "TestBot",
            "acquired_at": "2026-03-12T10:00:00Z",
            "expires_at": "2026-03-12T10:30:00Z",
            "reason": "testing"
        }"#;
        let lock: OpLock = serde_json::from_str(json).unwrap();
        assert_eq!(lock.resource, "github.issues");
        assert_eq!(lock.agent, "TestBot");
        assert_eq!(lock.reason.as_deref(), Some("testing"));
    }

    #[test]
    fn lock_deserialize_null_reason() {
        let json = r#"{
            "resource": "r",
            "agent": "a",
            "acquired_at": "2026-03-12T10:00:00Z",
            "expires_at": "2026-03-12T10:30:00Z",
            "reason": null
        }"#;
        let lock: OpLock = serde_json::from_str(json).unwrap();
        assert!(lock.reason.is_none());
    }

    // ── OpLock: Clone deep equality ─────────────────────────────

    #[test]
    fn lock_clone_preserves_all_fields() {
        let now = Utc::now();
        let lock = OpLock {
            resource: "res.x".to_owned(),
            agent: "agent.y".to_owned(),
            acquired_at: now,
            expires_at: now + Duration::minutes(42),
            reason: Some("deep clone test".to_owned()),
        };
        let cloned = lock.clone();
        assert_eq!(lock.resource, cloned.resource);
        assert_eq!(lock.agent, cloned.agent);
        assert_eq!(lock.acquired_at, cloned.acquired_at);
        assert_eq!(lock.expires_at, cloned.expires_at);
        assert_eq!(lock.reason, cloned.reason);
    }

    #[test]
    fn lock_clone_is_independent() {
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            reason: Some("orig".to_owned()),
        };
        let mut cloned = lock.clone();
        cloned.resource = "modified".to_owned();
        assert_eq!(lock.resource, "r");
        assert_eq!(cloned.resource, "modified");
    }

    // ── OpLock: Debug format ────────────────────────────────────

    #[test]
    fn lock_debug_contains_agent() {
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "SpecificAgent42".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            reason: None,
        };
        let debug = format!("{lock:?}");
        assert!(debug.contains("SpecificAgent42"));
    }

    #[test]
    fn lock_debug_contains_reason() {
        let lock = OpLock {
            resource: "r".to_owned(),
            agent: "a".to_owned(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            reason: Some("debug-reason".to_owned()),
        };
        let debug = format!("{lock:?}");
        assert!(debug.contains("debug-reason"));
    }

    // ── AcquireResult: Debug ────────────────────────────────────

    #[test]
    fn acquire_result_acquired_debug() {
        let result = AcquireResult::Acquired {
            lock: OpLock {
                resource: "r".to_owned(),
                agent: "a".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(1),
                reason: None,
            },
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("Acquired"));
    }

    #[test]
    fn acquire_result_conflict_debug() {
        let result = AcquireResult::Conflict {
            held_by: "Agent".to_owned(),
            expires_at: "t".to_owned(),
            remaining: "5m".to_owned(),
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("Conflict"));
        assert!(debug.contains("Agent"));
    }

    #[test]
    fn acquire_result_clone_acquired() {
        let result = AcquireResult::Acquired {
            lock: OpLock {
                resource: "r".to_owned(),
                agent: "a".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(5),
                reason: Some("c".to_owned()),
            },
        };
        let cloned = result.clone();
        assert!(cloned.is_acquired());
    }

    // ── CheckResult: Debug ──────────────────────────────────────

    #[test]
    fn check_result_free_debug() {
        let result = CheckResult::Free;
        let debug = format!("{result:?}");
        assert!(debug.contains("Free"));
    }

    #[test]
    fn check_result_held_by_self_debug() {
        let result = CheckResult::HeldBySelf {
            lock: OpLock {
                resource: "r".to_owned(),
                agent: "me".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(5),
                reason: None,
            },
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("HeldBySelf"));
    }

    #[test]
    fn check_result_held_by_other_debug() {
        let result = CheckResult::HeldByOther {
            held_by: "Other".to_owned(),
            expires_at: "t".to_owned(),
            remaining: "2m".to_owned(),
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("HeldByOther"));
        assert!(debug.contains("Other"));
    }

    #[test]
    fn check_result_clone_held_by_self() {
        let result = CheckResult::HeldBySelf {
            lock: OpLock {
                resource: "r".to_owned(),
                agent: "me".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(5),
                reason: Some("testing".to_owned()),
            },
        };
        let cloned = result.clone();
        let json = serde_json::to_value(&cloned).unwrap();
        assert_eq!(json["status"], "held_by_self");
    }

    #[test]
    fn check_result_clone_held_by_other() {
        let result = CheckResult::HeldByOther {
            held_by: "X".to_owned(),
            expires_at: "t".to_owned(),
            remaining: "1m".to_owned(),
        };
        let cloned = result.clone();
        let json = serde_json::to_value(&cloned).unwrap();
        assert_eq!(json["held_by"], "X");
    }

    // ── LockStore: TTL=0 edge case ─────────────────────────────

    #[test]
    fn acquire_with_zero_ttl() {
        let store = temp_store();
        let result = store.acquire("res", "Agent", 0, None).unwrap();
        // TTL=0 means expires immediately at acquired_at
        assert!(result.is_acquired());
        // But checking right after should show it expired (gc'd)
        let locks = store.list().unwrap();
        assert!(locks.is_empty());
    }

    #[test]
    fn acquire_with_large_ttl() {
        let store = temp_store();
        let result = store.acquire("res", "Agent", u32::MAX, None).unwrap();
        assert!(result.is_acquired());
        if let AcquireResult::Acquired { lock } = result {
            assert!(lock.is_active());
        }
    }

    // ── LockStore: corrupted data ───────────────────────────────

    #[test]
    fn load_corrupted_json_returns_error() {
        let store = temp_store();
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(store.data_path(), "not valid json!!!").unwrap();
        let result = store.list();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("corrupted"));
    }

    #[test]
    fn load_empty_json_file_returns_error() {
        let store = temp_store();
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(store.data_path(), "").unwrap();
        let result = store.list();
        assert!(result.is_err());
    }

    #[test]
    fn load_partial_json_returns_error() {
        let store = temp_store();
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(store.data_path(), "{\"locks\": {").unwrap();
        let result = store.list();
        assert!(result.is_err());
    }

    #[test]
    fn load_valid_empty_locks_json() {
        let store = temp_store();
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(store.data_path(), r#"{"locks": {}}"#).unwrap();
        let locks = store.list().unwrap();
        assert!(locks.is_empty());
    }

    // ── LockStore: data_path ────────────────────────────────────

    #[test]
    fn data_path_ends_with_locks_json() {
        let store = temp_store();
        let path = store.data_path();
        assert!(path.to_str().unwrap().ends_with("locks.json"));
    }

    // ── LockStore: multiple GC passes ───────────────────────────

    #[test]
    fn gc_removes_only_expired_locks() {
        let store = temp_store();
        let mut data = LockData::default();
        // Add one expired and one active lock
        data.locks.insert(
            "expired.res".to_owned(),
            OpLock {
                resource: "expired.res".to_owned(),
                agent: "Ghost".to_owned(),
                acquired_at: Utc::now() - Duration::hours(3),
                expires_at: Utc::now() - Duration::hours(1),
                reason: None,
            },
        );
        data.locks.insert(
            "active.res".to_owned(),
            OpLock {
                resource: "active.res".to_owned(),
                agent: "Alive".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                reason: None,
            },
        );
        std::fs::create_dir_all(store.dir()).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(store.data_path(), json).unwrap();

        let locks = store.list().unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].resource, "active.res");
    }

    #[test]
    fn gc_all_expired_results_in_empty() {
        let store = temp_store();
        let mut data = LockData::default();
        for i in 0..5 {
            data.locks.insert(
                format!("expired.{i}"),
                OpLock {
                    resource: format!("expired.{i}"),
                    agent: format!("Ghost{i}"),
                    acquired_at: Utc::now() - Duration::hours(3),
                    expires_at: Utc::now() - Duration::seconds(1),
                    reason: None,
                },
            );
        }
        std::fs::create_dir_all(store.dir()).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(store.data_path(), json).unwrap();

        assert_eq!(store.count().unwrap(), 0);
    }

    // ── LockStore: refresh semantics ────────────────────────────

    #[test]
    fn refresh_updates_expiry_time() {
        let store = temp_store();
        let r1 = store.acquire("res", "Agent", 10, None).unwrap();
        let r2 = store.acquire("res", "Agent", 60, None).unwrap();
        if let (AcquireResult::Acquired { lock: l1 }, AcquireResult::Acquired { lock: l2 }) =
            (r1, r2)
        {
            // Second acquisition should have later expiry
            assert!(l2.expires_at > l1.expires_at);
        } else {
            panic!("both should be acquired");
        }
    }

    #[test]
    fn refresh_updates_reason() {
        let store = temp_store();
        store
            .acquire("res", "Agent", 30, Some("first".to_owned()))
            .unwrap();
        let result = store
            .acquire("res", "Agent", 30, Some("second".to_owned()))
            .unwrap();
        if let AcquireResult::Acquired { lock } = result {
            assert_eq!(lock.reason.as_deref(), Some("second"));
        } else {
            panic!("expected Acquired");
        }
    }

    #[test]
    fn refresh_clears_reason_if_none() {
        let store = temp_store();
        store
            .acquire("res", "Agent", 30, Some("has reason".to_owned()))
            .unwrap();
        let result = store.acquire("res", "Agent", 30, None).unwrap();
        if let AcquireResult::Acquired { lock } = result {
            assert!(lock.reason.is_none());
        } else {
            panic!("expected Acquired");
        }
    }

    // ── LockStore: conflict details ─────────────────────────────

    #[test]
    fn conflict_contains_rfc3339_expiry() {
        let store = temp_store();
        store.acquire("res", "AgentA", 30, None).unwrap();
        let result = store.acquire("res", "AgentB", 30, None).unwrap();
        if let AcquireResult::Conflict { expires_at, .. } = result {
            // Should be a valid RFC3339 timestamp
            assert!(expires_at.contains('T'));
            assert!(expires_at.contains('+') || expires_at.contains('Z'));
        } else {
            panic!("expected Conflict");
        }
    }

    #[test]
    fn conflict_remaining_is_nonempty() {
        let store = temp_store();
        store.acquire("res", "AgentA", 30, None).unwrap();
        let result = store.acquire("res", "AgentB", 30, None).unwrap();
        if let AcquireResult::Conflict { remaining, .. } = result {
            assert!(!remaining.is_empty());
        } else {
            panic!("expected Conflict");
        }
    }

    // ── LockStore: release after expired ────────────────────────

    #[test]
    fn release_expired_lock_returns_false() {
        let store = temp_store();
        let mut data = LockData::default();
        data.locks.insert(
            "res".to_owned(),
            OpLock {
                resource: "res".to_owned(),
                agent: "Agent".to_owned(),
                acquired_at: Utc::now() - Duration::hours(2),
                expires_at: Utc::now() - Duration::hours(1),
                reason: None,
            },
        );
        std::fs::create_dir_all(store.dir()).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(store.data_path(), json).unwrap();

        // GC removes the expired lock before release can find it
        assert!(!store.release("res", "Agent").unwrap());
    }

    // ── LockStore: check with expired lock ──────────────────────

    #[test]
    fn check_expired_lock_shows_free() {
        let store = temp_store();
        let mut data = LockData::default();
        data.locks.insert(
            "res".to_owned(),
            OpLock {
                resource: "res".to_owned(),
                agent: "OldAgent".to_owned(),
                acquired_at: Utc::now() - Duration::hours(2),
                expires_at: Utc::now() - Duration::seconds(1),
                reason: None,
            },
        );
        std::fs::create_dir_all(store.dir()).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(store.data_path(), json).unwrap();

        let result = store.check("res", "AnyAgent").unwrap();
        assert!(matches!(result, CheckResult::Free));
    }

    // ── LockStore: list_by_agent with expired ───────────────────

    #[test]
    fn list_by_agent_excludes_expired() {
        let store = temp_store();
        let mut data = LockData::default();
        data.locks.insert(
            "expired.res".to_owned(),
            OpLock {
                resource: "expired.res".to_owned(),
                agent: "Agent".to_owned(),
                acquired_at: Utc::now() - Duration::hours(2),
                expires_at: Utc::now() - Duration::seconds(1),
                reason: None,
            },
        );
        data.locks.insert(
            "active.res".to_owned(),
            OpLock {
                resource: "active.res".to_owned(),
                agent: "Agent".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                reason: None,
            },
        );
        std::fs::create_dir_all(store.dir()).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(store.data_path(), json).unwrap();

        let locks = store.list_by_agent("Agent").unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].resource, "active.res");
    }

    // ── LockStore: release_all empty store ──────────────────────

    #[test]
    fn release_all_on_empty_store() {
        let store = temp_store();
        let released = store.release_all("Agent").unwrap();
        assert_eq!(released, 0);
    }

    #[test]
    fn release_all_does_not_save_when_zero() {
        let store = temp_store();
        // Don't create the dir - release_all with 0 should not attempt to save
        let released = store.release_all("Agent").unwrap();
        assert_eq!(released, 0);
        // data_path should not exist since no save was needed
        assert!(!store.data_path().exists());
    }

    // ── LockStore: count with expired ───────────────────────────

    #[test]
    fn count_excludes_expired() {
        let store = temp_store();
        let mut data = LockData::default();
        data.locks.insert(
            "expired".to_owned(),
            OpLock {
                resource: "expired".to_owned(),
                agent: "Ghost".to_owned(),
                acquired_at: Utc::now() - Duration::hours(2),
                expires_at: Utc::now() - Duration::seconds(1),
                reason: None,
            },
        );
        data.locks.insert(
            "active".to_owned(),
            OpLock {
                resource: "active".to_owned(),
                agent: "Alive".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                reason: None,
            },
        );
        std::fs::create_dir_all(store.dir()).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(store.data_path(), json).unwrap();

        assert_eq!(store.count().unwrap(), 1);
    }

    // ── LockStore: acquire after expired by different agent ─────

    #[test]
    fn acquire_after_expired_by_other_agent() {
        let store = temp_store();
        let mut data = LockData::default();
        data.locks.insert(
            "res".to_owned(),
            OpLock {
                resource: "res".to_owned(),
                agent: "OldAgent".to_owned(),
                acquired_at: Utc::now() - Duration::hours(2),
                expires_at: Utc::now() - Duration::seconds(1),
                reason: None,
            },
        );
        std::fs::create_dir_all(store.dir()).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(store.data_path(), json).unwrap();

        let result = store.acquire("res", "NewAgent", 30, None).unwrap();
        assert!(result.is_acquired());
        if let AcquireResult::Acquired { lock } = result {
            assert_eq!(lock.agent, "NewAgent");
        }
    }

    // ── LockStore: persistence across instances ─────────────────

    #[test]
    fn locks_persist_across_store_instances() {
        let dir = std::env::temp_dir().join(format!("fwc-lock-persist-{}", uuid::Uuid::new_v4()));
        let store1 = LockStore::new(dir.clone());
        store1.acquire("res", "Agent", 30, None).unwrap();

        let store2 = LockStore::new(dir);
        let locks = store2.list().unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].resource, "res");
    }

    #[test]
    fn release_persists_across_store_instances() {
        let dir =
            std::env::temp_dir().join(format!("fwc-lock-relpersist-{}", uuid::Uuid::new_v4()));
        let store1 = LockStore::new(dir.clone());
        store1.acquire("res", "Agent", 30, None).unwrap();
        store1.release("res", "Agent").unwrap();

        let store2 = LockStore::new(dir);
        assert_eq!(store2.count().unwrap(), 0);
    }

    // ── LockStore: many resources stress ────────────────────────

    #[test]
    fn acquire_many_resources() {
        let store = temp_store();
        for i in 0..20 {
            let resource = format!("resource.{i}");
            let result = store.acquire(&resource, "Agent", 30, None).unwrap();
            assert!(result.is_acquired());
        }
        assert_eq!(store.count().unwrap(), 20);
        let locks = store.list().unwrap();
        assert_eq!(locks.len(), 20);
    }

    #[test]
    fn release_all_many_resources() {
        let store = temp_store();
        for i in 0..10 {
            store
                .acquire(&format!("res.{i}"), "Agent", 30, None)
                .unwrap();
        }
        let released = store.release_all("Agent").unwrap();
        assert_eq!(released, 10);
        assert_eq!(store.count().unwrap(), 0);
    }

    // ── LockStore: check after acquire by same agent ────────────

    #[test]
    fn check_held_by_self_contains_lock_details() {
        let store = temp_store();
        store
            .acquire("res", "Agent", 30, Some("my reason".to_owned()))
            .unwrap();
        let result = store.check("res", "Agent").unwrap();
        match result {
            CheckResult::HeldBySelf { lock } => {
                assert_eq!(lock.resource, "res");
                assert_eq!(lock.agent, "Agent");
                assert_eq!(lock.reason.as_deref(), Some("my reason"));
            }
            other => panic!("expected HeldBySelf, got {other:?}"),
        }
    }

    // ── parse_ttl: more edge cases ──────────────────────────────

    #[test]
    fn parse_ttl_zero_minutes() {
        assert_eq!(parse_ttl("0m").unwrap(), 0);
    }

    #[test]
    fn parse_ttl_zero_hours() {
        assert_eq!(parse_ttl("0h").unwrap(), 0);
    }

    #[test]
    fn parse_ttl_zero_seconds() {
        assert_eq!(parse_ttl("0s").unwrap(), 0);
    }

    #[test]
    fn parse_ttl_zero_plain() {
        assert_eq!(parse_ttl("0").unwrap(), 0);
    }

    #[test]
    fn parse_ttl_huge_minutes() {
        assert_eq!(parse_ttl("9999m").unwrap(), 9999);
    }

    #[test]
    fn parse_ttl_huge_hours() {
        assert_eq!(parse_ttl("999h").unwrap(), 999 * 60);
    }

    #[test]
    fn parse_ttl_1s_rounds_up_to_1() {
        assert_eq!(parse_ttl("1s").unwrap(), 1);
    }

    #[test]
    fn parse_ttl_59s_rounds_up_to_1() {
        assert_eq!(parse_ttl("59s").unwrap(), 1);
    }

    #[test]
    fn parse_ttl_119s_rounds_up_to_2() {
        assert_eq!(parse_ttl("119s").unwrap(), 2);
    }

    #[test]
    fn parse_ttl_121s_rounds_up_to_3() {
        assert_eq!(parse_ttl("121s").unwrap(), 3);
    }

    #[test]
    fn parse_ttl_double_suffix_is_error() {
        assert!(parse_ttl("30mm").is_err());
        assert!(parse_ttl("2hh").is_err());
    }

    #[test]
    fn parse_ttl_float_is_error() {
        assert!(parse_ttl("2.5m").is_err());
        assert!(parse_ttl("1.5h").is_err());
    }

    #[test]
    fn parse_ttl_mixed_case_suffix_is_error() {
        // Only lowercase suffixes are recognized
        assert!(parse_ttl("30M").is_err());
        assert!(parse_ttl("2H").is_err());
        assert!(parse_ttl("60S").is_err());
    }

    #[test]
    fn parse_ttl_leading_zeros() {
        assert_eq!(parse_ttl("030m").unwrap(), 30);
        assert_eq!(parse_ttl("002h").unwrap(), 120);
    }

    #[test]
    fn parse_ttl_only_suffix_is_error() {
        assert!(parse_ttl("m").is_err());
        assert!(parse_ttl("h").is_err());
        assert!(parse_ttl("s").is_err());
    }

    #[test]
    fn parse_ttl_error_messages_contain_context() {
        let err = parse_ttl("badm").unwrap_err();
        assert!(err.contains("invalid TTL minutes"));

        let err = parse_ttl("badh").unwrap_err();
        assert!(err.contains("invalid TTL hours"));

        let err = parse_ttl("bads").unwrap_err();
        assert!(err.contains("invalid TTL seconds"));

        let err = parse_ttl("nope").unwrap_err();
        assert!(err.contains("invalid TTL"));
    }

    #[test]
    fn parse_ttl_empty_string_error_message() {
        let err = parse_ttl("").unwrap_err();
        assert!(err.contains("empty"));
    }

    // ── validate_resource: more edge cases ──────────────────────

    #[test]
    fn validate_resource_unicode_rejected() {
        assert!(validate_resource("caf\u{00e9}").is_err());
        assert!(validate_resource("\u{1f600}").is_err());
    }

    #[test]
    fn validate_resource_colon_rejected() {
        assert!(validate_resource("github:issues").is_err());
    }

    #[test]
    fn validate_resource_comma_rejected() {
        assert!(validate_resource("a,b").is_err());
    }

    #[test]
    fn validate_resource_semicolon_rejected() {
        assert!(validate_resource("a;b").is_err());
    }

    #[test]
    fn validate_resource_equals_rejected() {
        assert!(validate_resource("a=b").is_err());
    }

    #[test]
    fn validate_resource_pipe_rejected() {
        assert!(validate_resource("a|b").is_err());
    }

    #[test]
    fn validate_resource_backslash_rejected() {
        assert!(validate_resource("a\\b").is_err());
    }

    #[test]
    fn validate_resource_127_chars_ok() {
        let s = "a".repeat(127);
        assert!(validate_resource(&s).is_ok());
    }

    #[test]
    fn validate_resource_all_allowed_chars() {
        // Test every allowed character class
        assert!(validate_resource("abcdefghijklmnopqrstuvwxyz").is_ok());
        assert!(validate_resource("ABCDEFGHIJKLMNOPQRSTUVWXYZ").is_ok());
        assert!(validate_resource("0123456789").is_ok());
        assert!(validate_resource("-_.*").is_ok());
    }

    #[test]
    fn validate_resource_error_message_for_empty() {
        let err = validate_resource("").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn validate_resource_error_message_for_too_long() {
        let err = validate_resource(&"a".repeat(200)).unwrap_err();
        assert!(err.contains("too long"));
    }

    #[test]
    fn validate_resource_error_message_for_invalid_chars() {
        let err = validate_resource("bad!char").unwrap_err();
        assert!(err.contains("invalid characters"));
        assert!(err.contains("bad!char"));
    }

    // ── LockData: Default ───────────────────────────────────────

    #[test]
    fn lock_data_default_has_empty_locks() {
        let data = LockData::default();
        assert!(data.locks.is_empty());
    }

    #[test]
    fn lock_data_serde_roundtrip() {
        let mut data = LockData::default();
        data.locks.insert(
            "res".to_owned(),
            OpLock {
                resource: "res".to_owned(),
                agent: "a".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(5),
                reason: None,
            },
        );
        let json = serde_json::to_string(&data).unwrap();
        let restored: LockData = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.locks.len(), 1);
        assert!(restored.locks.contains_key("res"));
    }

    #[test]
    fn lock_data_empty_serde_roundtrip() {
        let data = LockData::default();
        let json = serde_json::to_string(&data).unwrap();
        let restored: LockData = serde_json::from_str(&json).unwrap();
        assert!(restored.locks.is_empty());
    }

    // ── LockStore: new constructor ──────────────────────────────

    #[test]
    fn lock_store_new_with_pathbuf() {
        let store = LockStore::new(PathBuf::from("/tmp/test-locks"));
        assert_eq!(store.dir(), Path::new("/tmp/test-locks"));
    }

    #[test]
    fn lock_store_new_with_string() {
        let store = LockStore::new("/tmp/test-locks");
        assert_eq!(store.dir(), Path::new("/tmp/test-locks"));
    }

    // ── AcquireResult: serialization tag format ─────────────────

    #[test]
    fn acquire_result_acquired_json_has_snake_case_tag() {
        let result = AcquireResult::Acquired {
            lock: OpLock {
                resource: "r".to_owned(),
                agent: "a".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(1),
                reason: None,
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"acquired\""));
    }

    #[test]
    fn acquire_result_conflict_json_has_snake_case_tag() {
        let result = AcquireResult::Conflict {
            held_by: "X".to_owned(),
            expires_at: "t".to_owned(),
            remaining: "5m".to_owned(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"conflict\""));
    }

    // ── CheckResult: serialization tag format ───────────────────

    #[test]
    fn check_result_free_json_has_snake_case_tag() {
        let result = CheckResult::Free;
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"free\""));
    }

    #[test]
    fn check_result_held_by_self_json_has_snake_case_tag() {
        let result = CheckResult::HeldBySelf {
            lock: OpLock {
                resource: "r".to_owned(),
                agent: "a".to_owned(),
                acquired_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(1),
                reason: None,
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"held_by_self\""));
    }

    #[test]
    fn check_result_held_by_other_json_has_snake_case_tag() {
        let result = CheckResult::HeldByOther {
            held_by: "X".to_owned(),
            expires_at: "t".to_owned(),
            remaining: "5m".to_owned(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"held_by_other\""));
    }

    // ── LockStore: acquire conflict details from check ──────────

    #[test]
    fn held_by_other_check_matches_acquire_conflict() {
        let store = temp_store();
        store
            .acquire("res", "AgentA", 30, Some("reason".to_owned()))
            .unwrap();

        // Check from AgentB's perspective
        let check = store.check("res", "AgentB").unwrap();
        match check {
            CheckResult::HeldByOther { held_by, .. } => {
                assert_eq!(held_by, "AgentA");
            }
            other => panic!("expected HeldByOther, got {other:?}"),
        }

        // Acquire from AgentB should also show conflict
        let acquire = store.acquire("res", "AgentB", 30, None).unwrap();
        match acquire {
            AcquireResult::Conflict { held_by, .. } => {
                assert_eq!(held_by, "AgentA");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    // ── LockStore: sequential operations ────────────────────────

    #[test]
    fn acquire_release_acquire_cycle() {
        let store = temp_store();
        for _ in 0..5 {
            let result = store.acquire("res", "Agent", 30, None).unwrap();
            assert!(result.is_acquired());
            assert!(store.release("res", "Agent").unwrap());
            let check = store.check("res", "Agent").unwrap();
            assert!(matches!(check, CheckResult::Free));
        }
    }

    #[test]
    fn interleaved_acquire_release_multiple_resources() {
        let store = temp_store();
        store.acquire("res.a", "Agent", 30, None).unwrap();
        store.acquire("res.b", "Agent", 30, None).unwrap();
        assert_eq!(store.count().unwrap(), 2);
        store.release("res.a", "Agent").unwrap();
        assert_eq!(store.count().unwrap(), 1);
        store.acquire("res.c", "Agent", 30, None).unwrap();
        assert_eq!(store.count().unwrap(), 2);
        store.release("res.b", "Agent").unwrap();
        store.release("res.c", "Agent").unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }
}
