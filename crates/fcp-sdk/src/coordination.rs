//! Chat coordination helpers shared by connector implementations.
//!
//! The types in this module model the connector-local part of thread ownership:
//! a stable claim key, a short-lived mention tracker, and a small ownership
//! checker that can be used by tests or in-process connector fixtures. Durable
//! backends such as Agent Mail reservations or mesh gossip can implement
//! [`ThreadOwnershipChecker`] without changing connector call sites.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::{ConnectorId, FcpError, ZoneId, async_trait};

/// Default chat ownership and mention TTL: five minutes.
pub const DEFAULT_THREAD_OWNERSHIP_TTL: Duration = Duration::from_secs(300);

/// FCP error code used when a peer owns a chat thread.
pub const THREAD_OWNED_BY_PEER_ERROR_CODE: u16 = 4090;

/// Connector-level policy for chat messages without a native thread id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmMode {
    /// Skip ownership checks for direct messages without a thread id.
    Skip,
    /// Treat the conversation id as both channel and thread id.
    #[default]
    TreatAsThread,
}

/// Agent identifier used in chat coordination decisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentId(String);

impl AgentId {
    /// Create an agent id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the raw agent id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deterministic redacted form for audit logs.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("agent:{}", fnv1a64(self.0.as_bytes()))
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for AgentId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for AgentId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl AsRef<str> for AgentId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Platform channel or conversation identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(String);

impl ChannelId {
    /// Create a channel id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the raw channel id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deterministic redacted form for audit logs.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("channel:{}", fnv1a64(self.0.as_bytes()))
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ChannelId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ChannelId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl AsRef<str> for ChannelId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Platform thread identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadId(String);

impl ThreadId {
    /// Create a thread id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the raw thread id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deterministic redacted form for audit logs.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("thread:{}", fnv1a64(self.0.as_bytes()))
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ThreadId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ThreadId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl AsRef<str> for ThreadId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Stable namespace for a chat ownership claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::struct_field_names)]
pub struct ClaimKey {
    zone_id: ZoneId,
    connector_id: ConnectorId,
    channel_id: ChannelId,
    thread_id: ThreadId,
}

impl ClaimKey {
    /// Create a claim key for a concrete chat thread.
    #[must_use]
    pub const fn new(
        zone_id: ZoneId,
        connector_id: ConnectorId,
        channel_id: ChannelId,
        thread_id: ThreadId,
    ) -> Self {
        Self {
            zone_id,
            connector_id,
            channel_id,
            thread_id,
        }
    }

    /// Create a claim key for a platform message.
    ///
    /// Returns `None` for threadless messages when [`DmMode::Skip`] is active.
    #[must_use]
    pub fn for_chat_message(
        zone_id: ZoneId,
        connector_id: ConnectorId,
        channel_id: ChannelId,
        thread_id: Option<ThreadId>,
        dm_mode: DmMode,
    ) -> Option<Self> {
        let thread_id = match thread_id {
            Some(thread_id) => thread_id,
            None if matches!(dm_mode, DmMode::TreatAsThread) => {
                ThreadId::new(channel_id.as_str().to_owned())
            }
            None => return None,
        };
        Some(Self::new(zone_id, connector_id, channel_id, thread_id))
    }

    /// Zone namespace for the claim.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Connector namespace for the claim.
    #[must_use]
    pub const fn connector_id(&self) -> &ConnectorId {
        &self.connector_id
    }

    /// Channel namespace for the claim.
    #[must_use]
    pub const fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    /// Thread namespace for the claim.
    #[must_use]
    pub const fn thread_id(&self) -> &ThreadId {
        &self.thread_id
    }

    /// Redacted key suitable for structured audit logs.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.zone_id.as_str(),
            self.connector_id.as_str(),
            self.channel_id.redacted(),
            self.thread_id.redacted()
        )
    }
}

/// Short-lived record that an agent was mentioned in a thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MentionRecord {
    agent_id: AgentId,
    observed_at: Instant,
    expires_at: Instant,
}

impl MentionRecord {
    /// Agent that was mentioned.
    #[must_use]
    pub const fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Time when the mention was observed.
    #[must_use]
    pub const fn observed_at(&self) -> Instant {
        self.observed_at
    }

    /// Time when the mention record expires.
    #[must_use]
    pub const fn expires_at(&self) -> Instant {
        self.expires_at
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// In-memory mention tracker with lazy expiration.
#[derive(Debug)]
pub struct MentionTracker {
    ttl: Duration,
    mentions: Mutex<HashMap<ClaimKey, HashMap<AgentId, MentionRecord>>>,
}

impl MentionTracker {
    /// Create an empty tracker with a custom TTL.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            mentions: Mutex::new(HashMap::new()),
        }
    }

    /// Create an empty tracker with the default TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configured mention TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Record that `agent_id` was mentioned in `key`.
    pub fn stamp(&self, key: ClaimKey, agent_id: AgentId, observed_at: Instant) {
        let record = MentionRecord {
            agent_id: agent_id.clone(),
            observed_at,
            expires_at: observed_at + self.ttl,
        };
        let mut mentions = self.lock_mentions();
        mentions.entry(key).or_default().insert(agent_id, record);
    }

    /// Return the active mention record for a specific agent, if present.
    #[must_use]
    pub fn record_for(
        &self,
        key: &ClaimKey,
        agent_id: &AgentId,
        now: Instant,
    ) -> Option<MentionRecord> {
        let mut mentions = self.lock_mentions();
        prune_mentions(&mut mentions, now);
        mentions
            .get(key)
            .and_then(|agents| agents.get(agent_id).cloned())
    }

    /// Return all active mentioned agents for the key.
    #[must_use]
    pub fn mentioned_agents(&self, key: &ClaimKey, now: Instant) -> Vec<AgentId> {
        let mut agents = {
            let mut mentions = self.lock_mentions();
            prune_mentions(&mut mentions, now);
            mentions
                .get(key)
                .map(|records| records.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        agents.sort();
        agents
    }

    /// Number of active mention records after lazy pruning.
    #[must_use]
    pub fn active_len(&self, now: Instant) -> usize {
        let mut mentions = self.lock_mentions();
        prune_mentions(&mut mentions, now);
        mentions.values().map(HashMap::len).sum()
    }

    fn lock_mentions(&self) -> MutexGuard<'_, HashMap<ClaimKey, HashMap<AgentId, MentionRecord>>> {
        self.mentions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for MentionTracker {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_THREAD_OWNERSHIP_TTL)
    }
}

/// Current owner record for a chat thread claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipRecord {
    owner_agent_id: AgentId,
    claimed_at: Instant,
    renewed_at: Instant,
    expires_at: Instant,
}

impl OwnershipRecord {
    /// Agent that currently owns the claim.
    #[must_use]
    pub const fn owner_agent_id(&self) -> &AgentId {
        &self.owner_agent_id
    }

    /// Time when the claim was first acquired.
    #[must_use]
    pub const fn claimed_at(&self) -> Instant {
        self.claimed_at
    }

    /// Time when the claim was last renewed.
    #[must_use]
    pub const fn renewed_at(&self) -> Instant {
        self.renewed_at
    }

    /// Time when the claim expires without renewal.
    #[must_use]
    pub const fn expires_at(&self) -> Instant {
        self.expires_at
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Result of a thread ownership claim attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The claimant may proceed.
    Granted(AgentId),
    /// A peer currently owns the thread.
    AlreadyOwned(AgentId),
    /// The backend could not make a reliable decision.
    Indeterminate(String),
}

impl ClaimOutcome {
    /// Returns true when the claimant may proceed.
    #[must_use]
    pub const fn is_granted(&self) -> bool {
        matches!(self, Self::Granted(_))
    }

    /// Owner that blocked the claim, if this is [`ClaimOutcome::AlreadyOwned`].
    #[must_use]
    pub const fn blocking_owner(&self) -> Option<&AgentId> {
        match self {
            Self::AlreadyOwned(owner) => Some(owner),
            Self::Granted(_) | Self::Indeterminate(_) => None,
        }
    }
}

/// Create the standard FCP error for a peer-owned chat thread.
#[must_use]
pub fn thread_owned_by_peer_error(owner_agent_id: &AgentId) -> FcpError {
    FcpError::Unauthorized {
        code: THREAD_OWNED_BY_PEER_ERROR_CODE,
        message: format!("thread_owned_by_peer:{owner_agent_id}"),
    }
}

/// Async claim backend used by connector call sites.
#[async_trait]
pub trait ThreadOwnershipChecker: Send + Sync {
    /// Claim ownership for `agent_id` on `key`.
    async fn claim(
        &self,
        cx: &fcp_async_core::Cx,
        key: ClaimKey,
        agent_id: AgentId,
    ) -> ClaimOutcome;
}

/// In-memory ownership checker for tests and single-process fixtures.
#[derive(Debug)]
pub struct InMemoryThreadOwnershipChecker {
    ttl: Duration,
    claims: Mutex<HashMap<ClaimKey, OwnershipRecord>>,
}

impl InMemoryThreadOwnershipChecker {
    /// Create an empty checker with a custom TTL.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            claims: Mutex::new(HashMap::new()),
        }
    }

    /// Create an empty checker with the default TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configured claim TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Synchronously claim a thread at a caller-supplied time.
    pub fn claim_now(&self, key: ClaimKey, agent_id: AgentId, now: Instant) -> ClaimOutcome {
        let mut claims = self.lock_claims();
        prune_claims(&mut claims, now);
        let outcome = match claims.get_mut(&key) {
            Some(record) if record.owner_agent_id == agent_id => {
                record.renewed_at = now;
                record.expires_at = now + self.ttl;
                ClaimOutcome::Granted(agent_id)
            }
            Some(record) => ClaimOutcome::AlreadyOwned(record.owner_agent_id.clone()),
            None => {
                claims.insert(
                    key,
                    OwnershipRecord {
                        owner_agent_id: agent_id.clone(),
                        claimed_at: now,
                        renewed_at: now,
                        expires_at: now + self.ttl,
                    },
                );
                ClaimOutcome::Granted(agent_id)
            }
        };
        drop(claims);
        outcome
    }

    /// Claim a thread while respecting active mention records.
    ///
    /// If one or more agents were mentioned and `agent_id` was not among them,
    /// the claim is denied before touching the ownership map. If multiple
    /// agents were mentioned, normal first-claim-wins semantics decide between
    /// them.
    pub fn claim_with_mentions_now(
        &self,
        mentions: &MentionTracker,
        key: ClaimKey,
        agent_id: AgentId,
        now: Instant,
    ) -> ClaimOutcome {
        let mentioned_agents = mentions.mentioned_agents(&key, now);
        if !mentioned_agents.iter().any(|agent| agent == &agent_id) {
            if let Some(owner) = mentioned_agents.first().cloned() {
                return ClaimOutcome::AlreadyOwned(owner);
            }
        }
        self.claim_now(key, agent_id, now)
    }

    /// Release a claim when the current owner matches.
    ///
    /// Returns true when a claim was removed.
    pub fn release(&self, key: &ClaimKey, agent_id: &AgentId, now: Instant) -> bool {
        let mut claims = self.lock_claims();
        prune_claims(&mut claims, now);
        let removed = if claims
            .get(key)
            .is_some_and(|record| &record.owner_agent_id == agent_id)
        {
            claims.remove(key);
            true
        } else {
            false
        };
        drop(claims);
        removed
    }

    /// Return the active owner record for a claim key.
    #[must_use]
    pub fn record_for(&self, key: &ClaimKey, now: Instant) -> Option<OwnershipRecord> {
        let mut claims = self.lock_claims();
        prune_claims(&mut claims, now);
        claims.get(key).cloned()
    }

    /// Number of active claims after lazy pruning.
    #[must_use]
    pub fn active_len(&self, now: Instant) -> usize {
        let mut claims = self.lock_claims();
        prune_claims(&mut claims, now);
        claims.len()
    }

    fn lock_claims(&self) -> MutexGuard<'_, HashMap<ClaimKey, OwnershipRecord>> {
        self.claims
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for InMemoryThreadOwnershipChecker {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_THREAD_OWNERSHIP_TTL)
    }
}

#[async_trait]
impl ThreadOwnershipChecker for InMemoryThreadOwnershipChecker {
    async fn claim(
        &self,
        _cx: &fcp_async_core::Cx,
        key: ClaimKey,
        agent_id: AgentId,
    ) -> ClaimOutcome {
        self.claim_now(key, agent_id, Instant::now())
    }
}

fn prune_mentions(mentions: &mut HashMap<ClaimKey, HashMap<AgentId, MentionRecord>>, now: Instant) {
    mentions.retain(|_, records| {
        records.retain(|_, record| !record.is_expired(now));
        !records.is_empty()
    });
}

fn prune_claims(claims: &mut HashMap<ClaimKey, OwnershipRecord>, now: Instant) {
    claims.retain(|_, record| !record.is_expired(now));
}

fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0001_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::{ConnectorId, ZoneId};

    fn connector(id: &'static str) -> ConnectorId {
        ConnectorId::from_static(id)
    }

    fn key_for(connector_id: ConnectorId) -> ClaimKey {
        ClaimKey::new(
            ZoneId::work(),
            connector_id,
            ChannelId::new("C123"),
            ThreadId::new("1700000000.000100"),
        )
    }

    fn agent(id: &str) -> AgentId {
        AgentId::new(id)
    }

    #[test]
    fn mention_tracker_records_and_expires_lazily() {
        let tracker = MentionTracker::with_ttl(Duration::from_secs(5));
        let key = key_for(connector("slack:chat:1.0.0"));
        let alice = agent("alice");
        let now = Instant::now();

        tracker.stamp(key.clone(), alice.clone(), now);
        assert_eq!(
            tracker
                .record_for(&key, &alice, now)
                .map(|record| record.agent_id().clone()),
            Some(alice.clone())
        );
        assert_eq!(tracker.active_len(now), 1);
        assert_eq!(tracker.active_len(now + Duration::from_secs(5)), 0);
        assert!(
            tracker
                .record_for(&key, &alice, now + Duration::from_secs(5))
                .is_none()
        );
    }

    #[test]
    fn mention_tracker_isolates_zones_and_connectors() {
        let tracker = MentionTracker::new();
        let slack_key = key_for(connector("slack:chat:1.0.0"));
        let discord_key = key_for(connector("discord:chat:1.0.0"));
        let private_key = ClaimKey::new(
            ZoneId::private(),
            connector("slack:chat:1.0.0"),
            ChannelId::new("C123"),
            ThreadId::new("1700000000.000100"),
        );
        let alice = agent("alice");
        let now = Instant::now();

        tracker.stamp(slack_key.clone(), alice.clone(), now);

        assert!(tracker.record_for(&slack_key, &alice, now).is_some());
        assert!(tracker.record_for(&discord_key, &alice, now).is_none());
        assert!(tracker.record_for(&private_key, &alice, now).is_none());
    }

    #[test]
    fn mention_tracker_keeps_multi_mentions_for_race_to_claim() {
        let tracker = MentionTracker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();

        tracker.stamp(key.clone(), agent("alice"), now);
        tracker.stamp(key.clone(), agent("bob"), now);

        assert_eq!(
            tracker.mentioned_agents(&key, now),
            vec![agent("alice"), agent("bob")]
        );
    }

    #[test]
    fn dm_mode_controls_threadless_claim_key_creation() {
        let channel = ChannelId::new("signal-dm-42");
        let skipped = ClaimKey::for_chat_message(
            ZoneId::work(),
            connector("signal:chat:1.0.0"),
            channel.clone(),
            None,
            DmMode::Skip,
        );
        assert!(skipped.is_none());

        let treated = ClaimKey::for_chat_message(
            ZoneId::work(),
            connector("signal:chat:1.0.0"),
            channel.clone(),
            None,
            DmMode::TreatAsThread,
        );
        assert_eq!(treated.as_ref().map(ClaimKey::channel_id), Some(&channel));
        assert_eq!(
            treated.as_ref().map(|key| key.thread_id().as_str()),
            Some(channel.as_str())
        );
    }

    #[test]
    fn first_claim_wins_and_second_agent_is_denied() {
        let checker = InMemoryThreadOwnershipChecker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();

        assert_eq!(
            checker.claim_now(key.clone(), agent("alice"), now),
            ClaimOutcome::Granted(agent("alice"))
        );
        assert_eq!(
            checker.claim_now(key, agent("bob"), now),
            ClaimOutcome::AlreadyOwned(agent("alice"))
        );
    }

    #[test]
    fn same_owner_renews_claim() {
        let checker = InMemoryThreadOwnershipChecker::with_ttl(Duration::from_secs(5));
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();
        let renewed_at = now + Duration::from_secs(2);

        assert!(
            checker
                .claim_now(key.clone(), agent("alice"), now)
                .is_granted()
        );
        assert!(
            checker
                .claim_now(key.clone(), agent("alice"), renewed_at)
                .is_granted()
        );

        let record = checker.record_for(&key, renewed_at);
        assert_eq!(record.as_ref().map(OwnershipRecord::claimed_at), Some(now));
        assert_eq!(
            record.as_ref().map(OwnershipRecord::renewed_at),
            Some(renewed_at)
        );
        assert_eq!(
            record.as_ref().map(OwnershipRecord::expires_at),
            Some(renewed_at + Duration::from_secs(5))
        );
    }

    #[test]
    fn stale_claim_can_be_recovered_by_peer() {
        let checker = InMemoryThreadOwnershipChecker::with_ttl(Duration::from_secs(5));
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();

        assert!(
            checker
                .claim_now(key.clone(), agent("alice"), now)
                .is_granted()
        );
        assert_eq!(checker.active_len(now + Duration::from_secs(5)), 0);
        assert_eq!(
            checker.claim_now(key, agent("bob"), now + Duration::from_secs(6)),
            ClaimOutcome::Granted(agent("bob"))
        );
    }

    #[test]
    fn owner_release_allows_handoff() {
        let checker = InMemoryThreadOwnershipChecker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();

        assert!(
            checker
                .claim_now(key.clone(), agent("alice"), now)
                .is_granted()
        );
        assert!(checker.release(&key, &agent("alice"), now));
        assert!(!checker.release(&key, &agent("alice"), now));
        assert_eq!(
            checker.claim_now(key, agent("bob"), now),
            ClaimOutcome::Granted(agent("bob"))
        );
    }

    #[test]
    fn connector_namespace_keeps_claims_independent() {
        let checker = InMemoryThreadOwnershipChecker::new();
        let slack_key = key_for(connector("slack:chat:1.0.0"));
        let discord_key = key_for(connector("discord:chat:1.0.0"));
        let now = Instant::now();

        assert!(
            checker
                .claim_now(slack_key, agent("alice"), now)
                .is_granted()
        );
        assert!(
            checker
                .claim_now(discord_key, agent("bob"), now)
                .is_granted()
        );
    }

    #[test]
    fn mention_preference_blocks_unmentioned_agent() {
        let tracker = MentionTracker::new();
        let checker = InMemoryThreadOwnershipChecker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();
        tracker.stamp(key.clone(), agent("alice"), now);

        assert_eq!(
            checker.claim_with_mentions_now(&tracker, key.clone(), agent("bob"), now),
            ClaimOutcome::AlreadyOwned(agent("alice"))
        );
        assert_eq!(
            checker.claim_with_mentions_now(&tracker, key, agent("alice"), now),
            ClaimOutcome::Granted(agent("alice"))
        );
    }

    #[test]
    fn multi_mentioned_agents_still_use_first_claim_wins() {
        let tracker = MentionTracker::new();
        let checker = InMemoryThreadOwnershipChecker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();
        tracker.stamp(key.clone(), agent("alice"), now);
        tracker.stamp(key.clone(), agent("bob"), now);

        assert_eq!(
            checker.claim_with_mentions_now(&tracker, key.clone(), agent("bob"), now),
            ClaimOutcome::Granted(agent("bob"))
        );
        assert_eq!(
            checker.claim_with_mentions_now(&tracker, key, agent("alice"), now),
            ClaimOutcome::AlreadyOwned(agent("bob"))
        );
    }

    #[test]
    fn thread_owned_error_uses_standard_unauthorized_code() {
        let err = thread_owned_by_peer_error(&agent("alice"));
        let unauthorized = match err {
            FcpError::Unauthorized { code, message } => Some((code, message)),
            _ => None,
        };
        assert_eq!(
            unauthorized,
            Some((
                THREAD_OWNED_BY_PEER_ERROR_CODE,
                "thread_owned_by_peer:alice".to_owned()
            ))
        );
    }

    #[test]
    fn redacted_ids_are_deterministic_and_hide_raw_values() {
        let agent_id = agent("alice@example.test");
        let key = key_for(connector("slack:chat:1.0.0"));

        assert_eq!(agent_id.redacted(), agent_id.redacted());
        assert!(!agent_id.redacted().contains("alice"));
        assert!(!key.redacted().contains("1700000000"));
    }
}
