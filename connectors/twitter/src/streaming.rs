//! Twitter Streaming Ingestion — filtered stream management.
//!
//! Implements bead yff.5: singleton-writer lease for long-lived stream connections,
//! backpressure and bounded buffers, strict parsing, and audit trail.
//!
//! All content received from Twitter is treated as tainted external input.

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// TweetField
// ─────────────────────────────────────────────────────────────────────────────

/// Fields that can be requested from the Twitter filtered stream API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TweetField {
    /// Tweet ID.
    Id,
    /// Tweet text body.
    Text,
    /// Author user ID.
    AuthorId,
    /// Timestamp.
    CreatedAt,
    /// ISO 639-1 language code.
    Lang,
    /// Source application.
    Source,
    /// Public engagement metrics.
    PublicMetrics,
    /// Referenced tweets (retweets, quotes, replies).
    ReferencedTweets,
    /// Entity annotations (hashtags, mentions, URLs).
    Entities,
    /// Media attachment keys.
    Attachments,
    /// Conversation thread ID.
    ConversationId,
}

impl TweetField {
    /// Wire name for the Twitter API query parameter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Text => "text",
            Self::AuthorId => "author_id",
            Self::CreatedAt => "created_at",
            Self::Lang => "lang",
            Self::Source => "source",
            Self::PublicMetrics => "public_metrics",
            Self::ReferencedTweets => "referenced_tweets",
            Self::Entities => "entities",
            Self::Attachments => "attachments",
            Self::ConversationId => "conversation_id",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Expansion
// ─────────────────────────────────────────────────────────────────────────────

/// Expansion types for the Twitter filtered stream API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expansion {
    /// Expand author user object.
    AuthorId,
    /// Expand referenced tweet objects.
    ReferencedTweetsId,
    /// Expand media objects from attachments.
    AttachmentsMediaKeys,
    /// Expand mentioned user objects.
    EntitiesMentionsUsername,
}

impl Expansion {
    /// Wire name for the Twitter API query parameter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorId => "author_id",
            Self::ReferencedTweetsId => "referenced_tweets.id",
            Self::AttachmentsMediaKeys => "attachments.media_keys",
            Self::EntitiesMentionsUsername => "entities.mentions.username",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReferenceType / ReferencedTweet
// ─────────────────────────────────────────────────────────────────────────────

/// Type of tweet reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceType {
    /// A retweet of another tweet.
    Retweeted,
    /// A quote tweet.
    Quoted,
    /// A reply to another tweet.
    RepliedTo,
}

/// A reference to another tweet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferencedTweet {
    /// Kind of reference.
    pub ref_type: ReferenceType,
    /// ID of the referenced tweet.
    pub id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// TweetMetrics
// ─────────────────────────────────────────────────────────────────────────────

/// Public engagement metrics for a tweet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TweetMetrics {
    /// Number of retweets.
    pub retweet_count: u64,
    /// Number of replies.
    pub reply_count: u64,
    /// Number of likes.
    pub like_count: u64,
    /// Number of quote tweets.
    pub quote_count: u64,
    /// Number of impressions (may not always be present).
    #[serde(default)]
    pub impression_count: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamEvent
// ─────────────────────────────────────────────────────────────────────────────

/// A structured event emitted from the filtered stream.
///
/// All string fields are tainted external input and must not be trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamEvent {
    /// The tweet ID.
    pub tweet_id: String,
    /// The tweet text body (tainted).
    pub text: String,
    /// The author's user ID.
    pub author_id: String,
    /// When the tweet was created (ISO-8601).
    #[serde(default)]
    pub created_at: Option<String>,
    /// IDs of rules that matched this tweet.
    pub matching_rules: Vec<String>,
    /// Public engagement metrics if requested.
    #[serde(default)]
    pub metrics: Option<TweetMetrics>,
    /// Referenced tweets (retweets, quotes, replies).
    #[serde(default)]
    pub referenced_tweets: Vec<ReferencedTweet>,
    /// ISO 639-1 language code.
    #[serde(default)]
    pub lang: Option<String>,
}

impl StreamEvent {
    /// Returns true if this event represents a retweet.
    #[must_use]
    pub fn is_retweet(&self) -> bool {
        self.referenced_tweets
            .iter()
            .any(|r| r.ref_type == ReferenceType::Retweeted)
    }

    /// Returns true if this event represents a reply.
    #[must_use]
    pub fn is_reply(&self) -> bool {
        self.referenced_tweets
            .iter()
            .any(|r| r.ref_type == ReferenceType::RepliedTo)
    }

    /// Returns true if this event represents a quote tweet.
    #[must_use]
    pub fn is_quote(&self) -> bool {
        self.referenced_tweets
            .iter()
            .any(|r| r.ref_type == ReferenceType::Quoted)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamRule / StreamRuleSet
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum length of a stream rule value.
const MAX_RULE_VALUE_LEN: usize = 512;

/// Maximum length of a stream rule tag.
const MAX_RULE_TAG_LEN: usize = 128;

/// A single filtered stream rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamRule {
    /// Server-assigned rule ID (None for new rules not yet persisted).
    #[serde(default)]
    pub id: Option<String>,
    /// The rule value (filter expression).
    pub value: String,
    /// An optional human-readable tag.
    #[serde(default)]
    pub tag: Option<String>,
}

impl StreamRule {
    /// Validate this rule.
    ///
    /// # Errors
    ///
    /// Returns an error string if the rule value is empty, exceeds 512 chars,
    /// or the tag exceeds 128 chars.
    pub fn validate(&self) -> Result<(), String> {
        if self.value.is_empty() {
            return Err("rule value must not be empty".into());
        }
        if self.value.len() > MAX_RULE_VALUE_LEN {
            return Err(format!(
                "rule value exceeds {MAX_RULE_VALUE_LEN} characters (got {})",
                self.value.len()
            ));
        }
        if let Some(tag) = &self.tag {
            if tag.len() > MAX_RULE_TAG_LEN {
                return Err(format!(
                    "rule tag exceeds {MAX_RULE_TAG_LEN} characters (got {})",
                    tag.len()
                ));
            }
        }
        Ok(())
    }
}

/// Default maximum number of rules in a rule set.
const DEFAULT_MAX_RULES: usize = 25;

/// A set of filtered stream rules with capacity limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRuleSet {
    /// Active rules.
    pub rules: Vec<StreamRule>,
    /// Maximum number of rules allowed.
    pub max_rules: usize,
}

impl Default for StreamRuleSet {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            max_rules: DEFAULT_MAX_RULES,
        }
    }
}

impl StreamRuleSet {
    /// Add a rule to the set.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule is invalid or the set is at capacity.
    pub fn add_rule(&mut self, rule: StreamRule) -> Result<(), String> {
        rule.validate()?;
        if self.rules.len() >= self.max_rules {
            return Err(format!(
                "rule set at capacity ({}/{})",
                self.rules.len(),
                self.max_rules
            ));
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Remove a rule by its ID.
    ///
    /// Returns `true` if a rule was removed, `false` if no rule matched.
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id.as_deref() != Some(rule_id));
        self.rules.len() < before
    }

    /// Remove all rules.
    pub fn clear(&mut self) {
        self.rules.clear();
    }

    /// Validate all rules in the set.
    ///
    /// # Errors
    ///
    /// Returns the first validation error encountered.
    pub fn validate(&self) -> Result<(), String> {
        if self.rules.len() > self.max_rules {
            return Err(format!(
                "too many rules ({}/{})",
                self.rules.len(),
                self.max_rules
            ));
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate().map_err(|e| format!("rule[{i}]: {e}"))?;
        }
        Ok(())
    }

    /// Number of rules currently in the set.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Default buffer capacity.
const DEFAULT_BUFFER_CAPACITY: usize = 1024;

/// Default maximum reconnect attempts.
const DEFAULT_MAX_RECONNECT: u32 = 10;

/// Configuration for a filtered stream connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Minutes of backfill to request on reconnect (0–5).
    #[serde(default)]
    pub backfill_minutes: Option<u8>,
    /// Tweet fields to request.
    #[serde(default)]
    pub tweet_fields: Vec<TweetField>,
    /// Expansions to request.
    #[serde(default)]
    pub expansions: Vec<Expansion>,
    /// Buffer capacity for stream events.
    pub buffer_capacity: usize,
    /// Maximum reconnection attempts before giving up.
    pub max_reconnect_attempts: u32,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            backfill_minutes: None,
            tweet_fields: Vec::new(),
            expansions: Vec::new(),
            buffer_capacity: DEFAULT_BUFFER_CAPACITY,
            max_reconnect_attempts: DEFAULT_MAX_RECONNECT,
        }
    }
}

/// Maximum allowed backfill minutes.
const MAX_BACKFILL_MINUTES: u8 = 5;

/// Maximum allowed buffer capacity.
const MAX_BUFFER_CAPACITY: usize = 100_000;

impl StreamConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if backfill minutes > 5, buffer capacity is zero,
    /// or buffer capacity is unreasonably large.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(mins) = self.backfill_minutes {
            if mins > MAX_BACKFILL_MINUTES {
                return Err(format!(
                    "backfill_minutes must be 0–{MAX_BACKFILL_MINUTES}, got {mins}"
                ));
            }
        }
        if self.buffer_capacity == 0 {
            return Err("buffer_capacity must be > 0".into());
        }
        if self.buffer_capacity > MAX_BUFFER_CAPACITY {
            return Err(format!(
                "buffer_capacity exceeds maximum of {MAX_BUFFER_CAPACITY}"
            ));
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OverflowPolicy / BufferStatus / StreamBuffer
// ─────────────────────────────────────────────────────────────────────────────

/// Policy for handling buffer overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverflowPolicy {
    /// Drop the oldest event to make room.
    DropOldest,
    /// Drop the incoming event.
    DropNewest,
    /// Block until space is available (signaled via backpressure).
    Block,
}

/// Snapshot of buffer status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferStatus {
    /// Current number of events in the buffer.
    pub current_size: usize,
    /// Maximum buffer capacity.
    pub capacity: usize,
    /// Total number of events dropped since creation.
    pub dropped_total: u64,
    /// Whether the buffer is full.
    pub is_full: bool,
}

/// Bounded buffer for stream events with configurable overflow policy.
#[derive(Debug, Clone)]
pub struct StreamBuffer {
    events: VecDeque<StreamEvent>,
    capacity: usize,
    dropped_count: u64,
    overflow_policy: OverflowPolicy,
}

impl StreamBuffer {
    /// Create a new buffer with the given capacity and overflow policy.
    ///
    /// # Panics
    ///
    /// Panics if capacity is zero.
    #[must_use]
    pub fn new(capacity: usize, overflow_policy: OverflowPolicy) -> Self {
        assert!(capacity > 0, "buffer capacity must be > 0");
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            dropped_count: 0,
            overflow_policy,
        }
    }

    /// Push an event into the buffer.
    ///
    /// Returns `true` if the event was accepted, `false` if it was dropped.
    /// Under [`OverflowPolicy::Block`] the buffer signals backpressure
    /// by returning `false` when full.
    pub fn push(&mut self, event: StreamEvent) -> bool {
        if self.events.len() < self.capacity {
            self.events.push_back(event);
            return true;
        }

        match self.overflow_policy {
            OverflowPolicy::DropOldest => {
                self.events.pop_front();
                self.dropped_count += 1;
                self.events.push_back(event);
                true
            }
            OverflowPolicy::DropNewest => {
                self.dropped_count += 1;
                false
            }
            OverflowPolicy::Block => false,
        }
    }

    /// Drain all events from the buffer.
    pub fn drain(&mut self) -> Vec<StreamEvent> {
        self.events.drain(..).collect()
    }

    /// Peek at the next event without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<&StreamEvent> {
        self.events.front()
    }

    /// Get current buffer status.
    #[must_use]
    pub fn status(&self) -> BufferStatus {
        BufferStatus {
            current_size: self.events.len(),
            capacity: self.capacity,
            dropped_total: self.dropped_count,
            is_full: self.events.len() >= self.capacity,
        }
    }

    /// Returns `true` if the buffer is applying backpressure (full with Block policy).
    #[must_use]
    pub fn is_backpressured(&self) -> bool {
        self.overflow_policy == OverflowPolicy::Block && self.events.len() >= self.capacity
    }

    /// Number of events currently in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamLease / LeaseManager
// ─────────────────────────────────────────────────────────────────────────────

/// Default lease duration in seconds (5 minutes).
const DEFAULT_LEASE_DURATION_SECS: u32 = 300;

/// A singleton-writer lease for a long-lived stream connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamLease {
    /// Unique lease identifier.
    pub lease_id: String,
    /// Identity of the lease holder (agent / process ID).
    pub holder: String,
    /// When the lease was acquired.
    pub acquired_at: SystemTime,
    /// When the lease expires.
    pub expires_at: SystemTime,
    /// Configuration snapshot at lease acquisition time.
    pub stream_config: StreamConfig,
}

impl StreamLease {
    /// Check whether this lease has expired (using current wall-clock time).
    #[must_use]
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    /// Check whether this lease has expired at a specific point in time.
    #[must_use]
    pub fn is_expired_at(&self, at: SystemTime) -> bool {
        at >= self.expires_at
    }

    /// Renew the lease, extending its expiration by `duration`.
    pub fn renew(&mut self, duration: Duration) {
        let now = SystemTime::now();
        self.expires_at = now + duration;
    }
}

/// Manager for singleton-writer stream leases.
#[derive(Debug, Clone)]
pub struct LeaseManager {
    active_lease: Option<StreamLease>,
    lease_duration_seconds: u32,
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self {
            active_lease: None,
            lease_duration_seconds: DEFAULT_LEASE_DURATION_SECS,
        }
    }
}

impl LeaseManager {
    /// Create a new lease manager with a custom lease duration.
    #[must_use]
    pub const fn with_duration(lease_duration_seconds: u32) -> Self {
        Self {
            active_lease: None,
            lease_duration_seconds,
        }
    }

    /// Attempt to acquire a lease for the given holder.
    ///
    /// # Errors
    ///
    /// Returns an error if a non-expired lease is already held by another holder.
    pub fn acquire(
        &mut self,
        holder: &str,
        lease_id: &str,
        config: StreamConfig,
    ) -> Result<StreamLease, String> {
        // If there is an active, non-expired lease held by someone else, reject.
        if let Some(existing) = &self.active_lease {
            if !existing.is_expired() && existing.holder != holder {
                return Err(format!("lease already held by '{}'", existing.holder));
            }
        }

        let now = SystemTime::now();
        let lease = StreamLease {
            lease_id: lease_id.to_string(),
            holder: holder.to_string(),
            acquired_at: now,
            expires_at: now + Duration::from_secs(u64::from(self.lease_duration_seconds)),
            stream_config: config,
        };
        self.active_lease = Some(lease.clone());
        Ok(lease)
    }

    /// Release the current lease (by the holder).
    ///
    /// Returns `true` if a lease was released, `false` if no lease was active.
    pub fn release(&mut self, holder: &str) -> bool {
        if let Some(lease) = &self.active_lease {
            if lease.holder == holder || lease.is_expired() {
                self.active_lease = None;
                return true;
            }
        }
        false
    }

    /// Returns `true` if a non-expired lease is currently held.
    #[must_use]
    pub fn is_held(&self) -> bool {
        self.active_lease.as_ref().is_some_and(|l| !l.is_expired())
    }

    /// Returns the holder of the current (non-expired) lease, if any.
    #[must_use]
    pub fn current_holder(&self) -> Option<&str> {
        self.active_lease
            .as_ref()
            .filter(|l| !l.is_expired())
            .map(|l| l.holder.as_str())
    }

    /// Get a reference to the active lease, if any.
    #[must_use]
    pub const fn active_lease(&self) -> Option<&StreamLease> {
        self.active_lease.as_ref()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamAuditEvent
// ─────────────────────────────────────────────────────────────────────────────

/// Action recorded in a stream audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Stream connection established.
    Connected,
    /// Stream disconnected.
    Disconnected,
    /// A rule was added.
    RuleAdded,
    /// A rule was removed.
    RuleRemoved,
    /// Buffer overflow occurred.
    BufferOverflow,
    /// Lease acquired.
    LeaseAcquired,
    /// Lease released.
    LeaseReleased,
}

/// An audit event for stream lifecycle and operational actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamAuditEvent {
    /// When the event occurred.
    pub timestamp: SystemTime,
    /// What action was performed.
    pub action: AuditAction,
    /// Free-form details about the event.
    pub details: String,
}

impl StreamAuditEvent {
    /// Create a new audit event with the current timestamp.
    #[must_use]
    pub fn now(action: AuditAction, details: impl Into<String>) -> Self {
        Self {
            timestamp: SystemTime::now(),
            action,
            details: details.into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TweetField ──────────────────────────────────────────────────────

    #[test]
    fn tweet_field_id_as_str() {
        assert_eq!(TweetField::Id.as_str(), "id");
    }

    #[test]
    fn tweet_field_text_as_str() {
        assert_eq!(TweetField::Text.as_str(), "text");
    }

    #[test]
    fn tweet_field_author_id_as_str() {
        assert_eq!(TweetField::AuthorId.as_str(), "author_id");
    }

    #[test]
    fn tweet_field_created_at_as_str() {
        assert_eq!(TweetField::CreatedAt.as_str(), "created_at");
    }

    #[test]
    fn tweet_field_lang_as_str() {
        assert_eq!(TweetField::Lang.as_str(), "lang");
    }

    #[test]
    fn tweet_field_source_as_str() {
        assert_eq!(TweetField::Source.as_str(), "source");
    }

    #[test]
    fn tweet_field_public_metrics_as_str() {
        assert_eq!(TweetField::PublicMetrics.as_str(), "public_metrics");
    }

    #[test]
    fn tweet_field_referenced_tweets_as_str() {
        assert_eq!(TweetField::ReferencedTweets.as_str(), "referenced_tweets");
    }

    #[test]
    fn tweet_field_entities_as_str() {
        assert_eq!(TweetField::Entities.as_str(), "entities");
    }

    #[test]
    fn tweet_field_attachments_as_str() {
        assert_eq!(TweetField::Attachments.as_str(), "attachments");
    }

    #[test]
    fn tweet_field_conversation_id_as_str() {
        assert_eq!(TweetField::ConversationId.as_str(), "conversation_id");
    }

    #[test]
    fn tweet_field_clone_eq() {
        let f = TweetField::Lang;
        let f2 = f;
        assert_eq!(f, f2);
    }

    #[test]
    fn tweet_field_debug() {
        let dbg = format!("{:?}", TweetField::Source);
        assert!(dbg.contains("Source"));
    }

    #[test]
    fn tweet_field_serde_roundtrip() {
        let field = TweetField::PublicMetrics;
        let json = serde_json::to_string(&field).unwrap();
        let back: TweetField = serde_json::from_str(&json).unwrap();
        assert_eq!(field, back);
    }

    // ── Expansion ───────────────────────────────────────────────────────

    #[test]
    fn expansion_author_id_as_str() {
        assert_eq!(Expansion::AuthorId.as_str(), "author_id");
    }

    #[test]
    fn expansion_referenced_tweets_id_as_str() {
        assert_eq!(
            Expansion::ReferencedTweetsId.as_str(),
            "referenced_tweets.id"
        );
    }

    #[test]
    fn expansion_attachments_media_keys_as_str() {
        assert_eq!(
            Expansion::AttachmentsMediaKeys.as_str(),
            "attachments.media_keys"
        );
    }

    #[test]
    fn expansion_entities_mentions_username_as_str() {
        assert_eq!(
            Expansion::EntitiesMentionsUsername.as_str(),
            "entities.mentions.username"
        );
    }

    #[test]
    fn expansion_clone_eq() {
        let e = Expansion::AuthorId;
        let e2 = e;
        assert_eq!(e, e2);
    }

    #[test]
    fn expansion_debug() {
        let dbg = format!("{:?}", Expansion::ReferencedTweetsId);
        assert!(dbg.contains("ReferencedTweetsId"));
    }

    #[test]
    fn expansion_serde_roundtrip() {
        let exp = Expansion::AttachmentsMediaKeys;
        let json = serde_json::to_string(&exp).unwrap();
        let back: Expansion = serde_json::from_str(&json).unwrap();
        assert_eq!(exp, back);
    }

    // ── ReferenceType / ReferencedTweet ─────────────────────────────────

    #[test]
    fn reference_type_retweeted() {
        assert_eq!(ReferenceType::Retweeted, ReferenceType::Retweeted);
        assert_ne!(ReferenceType::Retweeted, ReferenceType::Quoted);
    }

    #[test]
    fn reference_type_serde_roundtrip() {
        for rt in [
            ReferenceType::Retweeted,
            ReferenceType::Quoted,
            ReferenceType::RepliedTo,
        ] {
            let json = serde_json::to_string(&rt).unwrap();
            let back: ReferenceType = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, back);
        }
    }

    #[test]
    fn reference_type_debug() {
        let dbg = format!("{:?}", ReferenceType::RepliedTo);
        assert!(dbg.contains("RepliedTo"));
    }

    #[test]
    fn referenced_tweet_clone_eq() {
        let rt = ReferencedTweet {
            ref_type: ReferenceType::Quoted,
            id: "1234".into(),
        };
        let rt2 = rt.clone();
        assert_eq!(rt, rt2);
    }

    #[test]
    fn referenced_tweet_serde_roundtrip() {
        let rt = ReferencedTweet {
            ref_type: ReferenceType::Retweeted,
            id: "9999".into(),
        };
        let json = serde_json::to_string(&rt).unwrap();
        let back: ReferencedTweet = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, back);
    }

    // ── TweetMetrics ────────────────────────────────────────────────────

    #[test]
    fn tweet_metrics_serde_roundtrip() {
        let m = TweetMetrics {
            retweet_count: 10,
            reply_count: 5,
            like_count: 100,
            quote_count: 2,
            impression_count: Some(5000),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: TweetMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn tweet_metrics_no_impressions() {
        let m = TweetMetrics {
            retweet_count: 1,
            reply_count: 0,
            like_count: 3,
            quote_count: 0,
            impression_count: None,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: TweetMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.impression_count, None);
    }

    #[test]
    fn tweet_metrics_debug() {
        let m = TweetMetrics {
            retweet_count: 0,
            reply_count: 0,
            like_count: 0,
            quote_count: 0,
            impression_count: None,
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("TweetMetrics"));
    }

    #[test]
    fn tweet_metrics_clone_eq() {
        let m = TweetMetrics {
            retweet_count: 7,
            reply_count: 3,
            like_count: 42,
            quote_count: 1,
            impression_count: Some(999),
        };
        let m2 = m.clone();
        assert_eq!(m, m2);
    }

    // ── StreamEvent ─────────────────────────────────────────────────────

    fn make_event() -> StreamEvent {
        StreamEvent {
            tweet_id: "t1".into(),
            text: "hello world".into(),
            author_id: "a1".into(),
            created_at: Some("2026-01-01T00:00:00Z".into()),
            matching_rules: vec!["rule1".into()],
            metrics: None,
            referenced_tweets: vec![],
            lang: Some("en".into()),
        }
    }

    #[test]
    fn stream_event_is_retweet_false_when_no_refs() {
        let e = make_event();
        assert!(!e.is_retweet());
    }

    #[test]
    fn stream_event_is_reply_false_when_no_refs() {
        let e = make_event();
        assert!(!e.is_reply());
    }

    #[test]
    fn stream_event_is_quote_false_when_no_refs() {
        let e = make_event();
        assert!(!e.is_quote());
    }

    #[test]
    fn stream_event_is_retweet_true() {
        let mut e = make_event();
        e.referenced_tweets.push(ReferencedTweet {
            ref_type: ReferenceType::Retweeted,
            id: "rt1".into(),
        });
        assert!(e.is_retweet());
        assert!(!e.is_reply());
        assert!(!e.is_quote());
    }

    #[test]
    fn stream_event_is_reply_true() {
        let mut e = make_event();
        e.referenced_tweets.push(ReferencedTweet {
            ref_type: ReferenceType::RepliedTo,
            id: "rp1".into(),
        });
        assert!(e.is_reply());
        assert!(!e.is_retweet());
    }

    #[test]
    fn stream_event_is_quote_true() {
        let mut e = make_event();
        e.referenced_tweets.push(ReferencedTweet {
            ref_type: ReferenceType::Quoted,
            id: "q1".into(),
        });
        assert!(e.is_quote());
        assert!(!e.is_retweet());
    }

    #[test]
    fn stream_event_multiple_refs() {
        let mut e = make_event();
        e.referenced_tweets.push(ReferencedTweet {
            ref_type: ReferenceType::Retweeted,
            id: "rt1".into(),
        });
        e.referenced_tweets.push(ReferencedTweet {
            ref_type: ReferenceType::Quoted,
            id: "q1".into(),
        });
        assert!(e.is_retweet());
        assert!(e.is_quote());
        assert!(!e.is_reply());
    }

    #[test]
    fn stream_event_serde_roundtrip() {
        let e = make_event();
        let json = serde_json::to_string(&e).unwrap();
        let back: StreamEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn stream_event_debug() {
        let e = make_event();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("t1"));
    }

    #[test]
    fn stream_event_clone_eq() {
        let e = make_event();
        let e2 = e.clone();
        assert_eq!(e, e2);
    }

    #[test]
    fn stream_event_with_metrics() {
        let mut e = make_event();
        e.metrics = Some(TweetMetrics {
            retweet_count: 10,
            reply_count: 5,
            like_count: 100,
            quote_count: 2,
            impression_count: None,
        });
        let json = serde_json::to_string(&e).unwrap();
        let back: StreamEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.metrics.as_ref().unwrap().like_count, 100);
    }

    #[test]
    fn stream_event_no_created_at() {
        let mut e = make_event();
        e.created_at = None;
        assert!(e.created_at.is_none());
    }

    #[test]
    fn stream_event_no_lang() {
        let mut e = make_event();
        e.lang = None;
        assert!(e.lang.is_none());
    }

    #[test]
    fn stream_event_empty_matching_rules() {
        let mut e = make_event();
        e.matching_rules.clear();
        assert!(e.matching_rules.is_empty());
    }

    // ── StreamRule ───────────────────────────────────────────────────────

    #[test]
    fn stream_rule_valid() {
        let rule = StreamRule {
            id: Some("r1".into()),
            value: "rust lang".into(),
            tag: Some("tech".into()),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn stream_rule_empty_value_rejected() {
        let rule = StreamRule {
            id: None,
            value: String::new(),
            tag: None,
        };
        let err = rule.validate().unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn stream_rule_value_too_long() {
        let rule = StreamRule {
            id: None,
            value: "x".repeat(513),
            tag: None,
        };
        let err = rule.validate().unwrap_err();
        assert!(err.contains("512"));
    }

    #[test]
    fn stream_rule_value_at_max_len() {
        let rule = StreamRule {
            id: None,
            value: "x".repeat(512),
            tag: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn stream_rule_tag_too_long() {
        let rule = StreamRule {
            id: None,
            value: "test".into(),
            tag: Some("t".repeat(129)),
        };
        let err = rule.validate().unwrap_err();
        assert!(err.contains("128"));
    }

    #[test]
    fn stream_rule_tag_at_max_len() {
        let rule = StreamRule {
            id: None,
            value: "test".into(),
            tag: Some("t".repeat(128)),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn stream_rule_no_id_valid() {
        let rule = StreamRule {
            id: None,
            value: "filter".into(),
            tag: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn stream_rule_serde_roundtrip() {
        let rule = StreamRule {
            id: Some("r42".into()),
            value: "rust OR cargo".into(),
            tag: Some("dev".into()),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: StreamRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn stream_rule_clone_eq() {
        let rule = StreamRule {
            id: Some("r1".into()),
            value: "test".into(),
            tag: None,
        };
        let rule2 = rule.clone();
        assert_eq!(rule, rule2);
    }

    #[test]
    fn stream_rule_debug() {
        let rule = StreamRule {
            id: None,
            value: "debug test".into(),
            tag: None,
        };
        let dbg = format!("{rule:?}");
        assert!(dbg.contains("debug test"));
    }

    // ── StreamRuleSet ───────────────────────────────────────────────────

    #[test]
    fn rule_set_default_max_rules() {
        let set = StreamRuleSet::default();
        assert_eq!(set.max_rules, 25);
        assert_eq!(set.rule_count(), 0);
    }

    #[test]
    fn rule_set_add_rule() {
        let mut set = StreamRuleSet::default();
        let rule = StreamRule {
            id: None,
            value: "rust".into(),
            tag: None,
        };
        assert!(set.add_rule(rule).is_ok());
        assert_eq!(set.rule_count(), 1);
    }

    #[test]
    fn rule_set_add_rule_rejects_invalid() {
        let mut set = StreamRuleSet::default();
        let rule = StreamRule {
            id: None,
            value: String::new(),
            tag: None,
        };
        assert!(set.add_rule(rule).is_err());
    }

    #[test]
    fn rule_set_add_rule_at_capacity() {
        let mut set = StreamRuleSet {
            rules: Vec::new(),
            max_rules: 2,
        };
        let r1 = StreamRule {
            id: None,
            value: "a".into(),
            tag: None,
        };
        let r2 = StreamRule {
            id: None,
            value: "b".into(),
            tag: None,
        };
        let r3 = StreamRule {
            id: None,
            value: "c".into(),
            tag: None,
        };
        assert!(set.add_rule(r1).is_ok());
        assert!(set.add_rule(r2).is_ok());
        let err = set.add_rule(r3).unwrap_err();
        assert!(err.contains("capacity"));
    }

    #[test]
    fn rule_set_remove_rule_found() {
        let mut set = StreamRuleSet::default();
        set.rules.push(StreamRule {
            id: Some("r1".into()),
            value: "test".into(),
            tag: None,
        });
        assert!(set.remove_rule("r1"));
        assert_eq!(set.rule_count(), 0);
    }

    #[test]
    fn rule_set_remove_rule_not_found() {
        let mut set = StreamRuleSet::default();
        assert!(!set.remove_rule("nonexistent"));
    }

    #[test]
    fn rule_set_remove_rule_without_id() {
        let mut set = StreamRuleSet::default();
        set.rules.push(StreamRule {
            id: None,
            value: "test".into(),
            tag: None,
        });
        // Rules without id won't match any ID-based removal
        assert!(!set.remove_rule("any"));
        assert_eq!(set.rule_count(), 1);
    }

    #[test]
    fn rule_set_clear() {
        let mut set = StreamRuleSet::default();
        set.rules.push(StreamRule {
            id: None,
            value: "a".into(),
            tag: None,
        });
        set.rules.push(StreamRule {
            id: None,
            value: "b".into(),
            tag: None,
        });
        set.clear();
        assert_eq!(set.rule_count(), 0);
    }

    #[test]
    fn rule_set_validate_ok() {
        let mut set = StreamRuleSet::default();
        set.rules.push(StreamRule {
            id: None,
            value: "valid".into(),
            tag: None,
        });
        assert!(set.validate().is_ok());
    }

    #[test]
    fn rule_set_validate_too_many() {
        let set = StreamRuleSet {
            rules: (0..30)
                .map(|i| StreamRule {
                    id: None,
                    value: format!("rule{i}"),
                    tag: None,
                })
                .collect(),
            max_rules: 25,
        };
        let err = set.validate().unwrap_err();
        assert!(err.contains("too many"));
    }

    #[test]
    fn rule_set_validate_invalid_rule() {
        let set = StreamRuleSet {
            rules: vec![StreamRule {
                id: None,
                value: String::new(),
                tag: None,
            }],
            max_rules: 25,
        };
        let err = set.validate().unwrap_err();
        assert!(err.contains("rule[0]"));
    }

    #[test]
    fn rule_set_serde_roundtrip() {
        let set = StreamRuleSet {
            rules: vec![StreamRule {
                id: Some("r1".into()),
                value: "test".into(),
                tag: Some("tag1".into()),
            }],
            max_rules: 10,
        };
        let json = serde_json::to_string(&set).unwrap();
        let back: StreamRuleSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rule_count(), 1);
        assert_eq!(back.max_rules, 10);
    }

    #[test]
    fn rule_set_debug() {
        let set = StreamRuleSet::default();
        let dbg = format!("{set:?}");
        assert!(dbg.contains("StreamRuleSet"));
    }

    // ── StreamConfig ────────────────────────────────────────────────────

    #[test]
    fn stream_config_default() {
        let cfg = StreamConfig::default();
        assert_eq!(cfg.buffer_capacity, 1024);
        assert_eq!(cfg.max_reconnect_attempts, 10);
        assert!(cfg.backfill_minutes.is_none());
        assert!(cfg.tweet_fields.is_empty());
        assert!(cfg.expansions.is_empty());
    }

    #[test]
    fn stream_config_validate_ok() {
        let cfg = StreamConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn stream_config_backfill_too_high() {
        let cfg = StreamConfig {
            backfill_minutes: Some(6),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("backfill"));
    }

    #[test]
    fn stream_config_backfill_at_max() {
        let cfg = StreamConfig {
            backfill_minutes: Some(5),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn stream_config_zero_buffer() {
        let cfg = StreamConfig {
            buffer_capacity: 0,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("buffer_capacity"));
    }

    #[test]
    fn stream_config_huge_buffer() {
        let cfg = StreamConfig {
            buffer_capacity: 200_000,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("maximum"));
    }

    #[test]
    fn stream_config_max_buffer_ok() {
        let cfg = StreamConfig {
            buffer_capacity: 100_000,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn stream_config_serde_roundtrip() {
        let cfg = StreamConfig {
            backfill_minutes: Some(3),
            tweet_fields: vec![TweetField::Id, TweetField::Text],
            expansions: vec![Expansion::AuthorId],
            buffer_capacity: 512,
            max_reconnect_attempts: 5,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: StreamConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.backfill_minutes, Some(3));
        assert_eq!(back.buffer_capacity, 512);
    }

    #[test]
    fn stream_config_debug() {
        let cfg = StreamConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("StreamConfig"));
    }

    #[test]
    fn stream_config_clone() {
        let cfg = StreamConfig {
            backfill_minutes: Some(2),
            tweet_fields: vec![TweetField::Lang],
            expansions: vec![],
            buffer_capacity: 256,
            max_reconnect_attempts: 3,
        };
        let cloned = cfg.clone();
        // Use original after clone to prove both are valid
        assert_eq!(cfg.backfill_minutes, Some(2));
        assert_eq!(cloned.buffer_capacity, 256);
    }

    // ── OverflowPolicy ─────────────────────────────────────────────────

    #[test]
    fn overflow_policy_eq() {
        assert_eq!(OverflowPolicy::DropOldest, OverflowPolicy::DropOldest);
        assert_ne!(OverflowPolicy::DropOldest, OverflowPolicy::DropNewest);
        assert_ne!(OverflowPolicy::Block, OverflowPolicy::DropNewest);
    }

    #[test]
    fn overflow_policy_debug() {
        let dbg = format!("{:?}", OverflowPolicy::Block);
        assert!(dbg.contains("Block"));
    }

    #[test]
    fn overflow_policy_serde_roundtrip() {
        for policy in [
            OverflowPolicy::DropOldest,
            OverflowPolicy::DropNewest,
            OverflowPolicy::Block,
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let back: OverflowPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, back);
        }
    }

    // ── BufferStatus ────────────────────────────────────────────────────

    #[test]
    fn buffer_status_serde_roundtrip() {
        let bs = BufferStatus {
            current_size: 10,
            capacity: 100,
            dropped_total: 5,
            is_full: false,
        };
        let json = serde_json::to_string(&bs).unwrap();
        let back: BufferStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(bs, back);
    }

    #[test]
    fn buffer_status_debug() {
        let bs = BufferStatus {
            current_size: 0,
            capacity: 10,
            dropped_total: 0,
            is_full: false,
        };
        let dbg = format!("{bs:?}");
        assert!(dbg.contains("BufferStatus"));
    }

    // ── StreamBuffer ────────────────────────────────────────────────────

    #[test]
    fn buffer_new_empty() {
        let buf = StreamBuffer::new(10, OverflowPolicy::DropOldest);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn buffer_zero_capacity_panics() {
        let _ = StreamBuffer::new(0, OverflowPolicy::DropOldest);
    }

    #[test]
    fn buffer_push_and_peek() {
        let mut buf = StreamBuffer::new(10, OverflowPolicy::DropOldest);
        let accepted = buf.push(make_event());
        assert!(accepted);
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
        assert_eq!(buf.peek().unwrap().tweet_id, "t1");
    }

    #[test]
    fn buffer_drain() {
        let mut buf = StreamBuffer::new(10, OverflowPolicy::DropOldest);
        buf.push(make_event());
        buf.push(make_event());
        let events = buf.drain();
        assert_eq!(events.len(), 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn buffer_drop_oldest_on_overflow() {
        let mut buf = StreamBuffer::new(2, OverflowPolicy::DropOldest);
        let mut e1 = make_event();
        e1.tweet_id = "first".into();
        let mut e2 = make_event();
        e2.tweet_id = "second".into();
        let mut e3 = make_event();
        e3.tweet_id = "third".into();

        buf.push(e1);
        buf.push(e2);
        let accepted = buf.push(e3);

        assert!(accepted);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.peek().unwrap().tweet_id, "second");

        let status = buf.status();
        assert_eq!(status.dropped_total, 1);
    }

    #[test]
    fn buffer_drop_newest_on_overflow() {
        let mut buf = StreamBuffer::new(2, OverflowPolicy::DropNewest);
        let mut e1 = make_event();
        e1.tweet_id = "first".into();
        let mut e2 = make_event();
        e2.tweet_id = "second".into();
        let mut e3 = make_event();
        e3.tweet_id = "third".into();

        buf.push(e1);
        buf.push(e2);
        let accepted = buf.push(e3);

        assert!(!accepted);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.peek().unwrap().tweet_id, "first");

        let status = buf.status();
        assert_eq!(status.dropped_total, 1);
    }

    #[test]
    fn buffer_block_on_overflow() {
        let mut buf = StreamBuffer::new(2, OverflowPolicy::Block);
        buf.push(make_event());
        buf.push(make_event());

        assert!(!buf.push(make_event()));
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.status().dropped_total, 0);
    }

    #[test]
    fn buffer_status_is_full() {
        let mut buf = StreamBuffer::new(2, OverflowPolicy::DropNewest);
        buf.push(make_event());
        assert!(!buf.status().is_full);
        buf.push(make_event());
        assert!(buf.status().is_full);
    }

    #[test]
    fn buffer_is_backpressured_block_full() {
        let mut buf = StreamBuffer::new(1, OverflowPolicy::Block);
        assert!(!buf.is_backpressured());
        buf.push(make_event());
        assert!(buf.is_backpressured());
    }

    #[test]
    fn buffer_is_backpressured_drop_oldest_not() {
        let mut buf = StreamBuffer::new(1, OverflowPolicy::DropOldest);
        buf.push(make_event());
        assert!(!buf.is_backpressured());
    }

    #[test]
    fn buffer_peek_empty() {
        let buf = StreamBuffer::new(5, OverflowPolicy::DropOldest);
        assert!(buf.peek().is_none());
    }

    #[test]
    fn buffer_drain_empty() {
        let mut buf = StreamBuffer::new(5, OverflowPolicy::DropOldest);
        assert!(buf.drain().is_empty());
    }

    #[test]
    fn buffer_multiple_drops_accumulate() {
        let mut buf = StreamBuffer::new(1, OverflowPolicy::DropOldest);
        for i in 0..5 {
            let mut e = make_event();
            e.tweet_id = format!("t{i}");
            buf.push(e);
        }
        assert_eq!(buf.status().dropped_total, 4);
        assert_eq!(buf.peek().unwrap().tweet_id, "t4");
    }

    #[test]
    fn buffer_status_capacity() {
        let buf = StreamBuffer::new(42, OverflowPolicy::Block);
        assert_eq!(buf.status().capacity, 42);
    }

    #[test]
    fn buffer_debug() {
        let buf = StreamBuffer::new(5, OverflowPolicy::DropOldest);
        let dbg = format!("{buf:?}");
        assert!(dbg.contains("StreamBuffer"));
    }

    // ── StreamLease ─────────────────────────────────────────────────────

    fn make_lease(secs_from_now: u64) -> StreamLease {
        let now = SystemTime::now();
        StreamLease {
            lease_id: "lease-1".into(),
            holder: "agent-a".into(),
            acquired_at: now,
            expires_at: now + Duration::from_secs(secs_from_now),
            stream_config: StreamConfig::default(),
        }
    }

    #[test]
    fn lease_not_expired() {
        let lease = make_lease(300);
        assert!(!lease.is_expired());
    }

    #[test]
    fn lease_expired_in_past() {
        let now = SystemTime::now();
        let lease = StreamLease {
            lease_id: "l1".into(),
            holder: "h1".into(),
            acquired_at: now - Duration::from_secs(600),
            expires_at: now - Duration::from_secs(1),
            stream_config: StreamConfig::default(),
        };
        assert!(lease.is_expired());
    }

    #[test]
    fn lease_is_expired_at_future() {
        let lease = make_lease(300);
        let far_future = SystemTime::now() + Duration::from_secs(600);
        assert!(lease.is_expired_at(far_future));
    }

    #[test]
    fn lease_is_expired_at_past() {
        let lease = make_lease(300);
        let past = SystemTime::now() - Duration::from_secs(1);
        assert!(!lease.is_expired_at(past));
    }

    #[test]
    fn lease_renew() {
        let mut lease = make_lease(10);
        let old_expires = lease.expires_at;
        // Small sleep equivalent: just renew with a longer duration
        lease.renew(Duration::from_secs(600));
        assert!(lease.expires_at > old_expires);
    }

    #[test]
    fn lease_debug() {
        let lease = make_lease(60);
        let dbg = format!("{lease:?}");
        assert!(dbg.contains("StreamLease"));
    }

    #[test]
    fn lease_clone() {
        let lease = make_lease(60);
        let lease2 = lease.clone();
        assert_eq!(lease.lease_id, lease2.lease_id);
        assert_eq!(lease.holder, lease2.holder);
    }

    #[test]
    fn lease_serde_roundtrip() {
        let lease = make_lease(300);
        let json = serde_json::to_string(&lease).unwrap();
        let back: StreamLease = serde_json::from_str(&json).unwrap();
        assert_eq!(back.lease_id, "lease-1");
        assert_eq!(back.holder, "agent-a");
    }

    // ── LeaseManager ────────────────────────────────────────────────────

    #[test]
    fn lease_manager_default_no_lease() {
        let mgr = LeaseManager::default();
        assert!(!mgr.is_held());
        assert!(mgr.current_holder().is_none());
    }

    #[test]
    fn lease_manager_with_duration() {
        let mgr = LeaseManager::with_duration(60);
        assert!(!mgr.is_held());
        assert_eq!(mgr.lease_duration_seconds, 60);
    }

    #[test]
    fn lease_manager_acquire_ok() {
        let mut mgr = LeaseManager::default();
        let lease = mgr
            .acquire("agent-a", "l1", StreamConfig::default())
            .unwrap();
        assert_eq!(lease.holder, "agent-a");
        assert!(mgr.is_held());
        assert_eq!(mgr.current_holder(), Some("agent-a"));
    }

    #[test]
    fn lease_manager_acquire_rejects_second_holder() {
        let mut mgr = LeaseManager::default();
        mgr.acquire("agent-a", "l1", StreamConfig::default())
            .unwrap();
        let err = mgr
            .acquire("agent-b", "l2", StreamConfig::default())
            .unwrap_err();
        assert!(err.contains("agent-a"));
    }

    #[test]
    fn lease_manager_acquire_allows_same_holder() {
        let mut mgr = LeaseManager::default();
        mgr.acquire("agent-a", "l1", StreamConfig::default())
            .unwrap();
        let lease = mgr
            .acquire("agent-a", "l2", StreamConfig::default())
            .unwrap();
        assert_eq!(lease.lease_id, "l2");
    }

    #[test]
    fn lease_manager_acquire_after_expiry() {
        let mut mgr = LeaseManager::with_duration(0);
        mgr.acquire("agent-a", "l1", StreamConfig::default())
            .unwrap();
        // lease_duration_seconds=0 means instant expiry
        let lease = mgr
            .acquire("agent-b", "l2", StreamConfig::default())
            .unwrap();
        assert_eq!(lease.holder, "agent-b");
    }

    #[test]
    fn lease_manager_release_by_holder() {
        let mut mgr = LeaseManager::default();
        mgr.acquire("agent-a", "l1", StreamConfig::default())
            .unwrap();
        assert!(mgr.release("agent-a"));
        assert!(!mgr.is_held());
    }

    #[test]
    fn lease_manager_release_wrong_holder() {
        let mut mgr = LeaseManager::default();
        mgr.acquire("agent-a", "l1", StreamConfig::default())
            .unwrap();
        assert!(!mgr.release("agent-b"));
        assert!(mgr.is_held());
    }

    #[test]
    fn lease_manager_release_no_lease() {
        let mut mgr = LeaseManager::default();
        assert!(!mgr.release("anyone"));
    }

    #[test]
    fn lease_manager_current_holder_after_release() {
        let mut mgr = LeaseManager::default();
        mgr.acquire("agent-a", "l1", StreamConfig::default())
            .unwrap();
        mgr.release("agent-a");
        assert!(mgr.current_holder().is_none());
    }

    #[test]
    fn lease_manager_active_lease_some() {
        let mut mgr = LeaseManager::default();
        mgr.acquire("agent-a", "l1", StreamConfig::default())
            .unwrap();
        assert!(mgr.active_lease().is_some());
    }

    #[test]
    fn lease_manager_active_lease_none() {
        let mgr = LeaseManager::default();
        assert!(mgr.active_lease().is_none());
    }

    #[test]
    fn lease_manager_debug() {
        let mgr = LeaseManager::default();
        let dbg = format!("{mgr:?}");
        assert!(dbg.contains("LeaseManager"));
    }

    #[test]
    fn lease_manager_clone() {
        let mut mgr = LeaseManager::default();
        mgr.acquire("agent-a", "l1", StreamConfig::default())
            .unwrap();
        let mgr2 = mgr.clone();
        assert!(mgr2.is_held());
        assert_eq!(mgr2.current_holder(), Some("agent-a"));
    }

    // ── AuditAction ─────────────────────────────────────────────────────

    #[test]
    fn audit_action_eq() {
        assert_eq!(AuditAction::Connected, AuditAction::Connected);
        assert_ne!(AuditAction::Connected, AuditAction::Disconnected);
    }

    #[test]
    fn audit_action_debug() {
        let dbg = format!("{:?}", AuditAction::BufferOverflow);
        assert!(dbg.contains("BufferOverflow"));
    }

    #[test]
    fn audit_action_serde_roundtrip() {
        for action in [
            AuditAction::Connected,
            AuditAction::Disconnected,
            AuditAction::RuleAdded,
            AuditAction::RuleRemoved,
            AuditAction::BufferOverflow,
            AuditAction::LeaseAcquired,
            AuditAction::LeaseReleased,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let back: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn audit_action_clone() {
        let a = AuditAction::RuleAdded;
        let a2 = a.clone();
        assert_eq!(a, a2);
    }

    // ── StreamAuditEvent ────────────────────────────────────────────────

    #[test]
    fn stream_audit_event_now() {
        let evt = StreamAuditEvent::now(AuditAction::Connected, "stream started");
        assert_eq!(evt.action, AuditAction::Connected);
        assert_eq!(evt.details, "stream started");
    }

    #[test]
    fn stream_audit_event_debug() {
        let evt = StreamAuditEvent::now(AuditAction::Disconnected, "timeout");
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("StreamAuditEvent"));
    }

    #[test]
    fn stream_audit_event_clone() {
        let evt = StreamAuditEvent::now(AuditAction::LeaseAcquired, "holder=agent-a");
        let evt2 = evt.clone();
        assert_eq!(evt.action, evt2.action);
        assert_eq!(evt.details, evt2.details);
    }

    #[test]
    fn stream_audit_event_serde_roundtrip() {
        let evt = StreamAuditEvent::now(AuditAction::RuleRemoved, "rule r1 deleted");
        let json = serde_json::to_string(&evt).unwrap();
        let back: StreamAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, AuditAction::RuleRemoved);
        assert_eq!(back.details, "rule r1 deleted");
    }

    #[test]
    fn stream_audit_event_buffer_overflow() {
        let evt = StreamAuditEvent::now(AuditAction::BufferOverflow, "dropped 5 events");
        assert_eq!(evt.action, AuditAction::BufferOverflow);
    }

    #[test]
    fn stream_audit_event_lease_released() {
        let evt = StreamAuditEvent::now(AuditAction::LeaseReleased, "agent-a released");
        assert_eq!(evt.details, "agent-a released");
    }

    // ── Integration: buffer + lease + audit ─────────────────────────────

    #[test]
    fn integration_full_lifecycle() {
        // Acquire lease
        let mut mgr = LeaseManager::with_duration(300);
        let config = StreamConfig {
            buffer_capacity: 3,
            ..Default::default()
        };
        let _audit1 = StreamAuditEvent::now(AuditAction::LeaseAcquired, "agent-a");
        let _lease = mgr.acquire("agent-a", "l1", config).unwrap();
        assert!(mgr.is_held());

        // Add rules
        let mut rules = StreamRuleSet::default();
        rules
            .add_rule(StreamRule {
                id: None,
                value: "rust lang".into(),
                tag: Some("tech".into()),
            })
            .unwrap();
        let _audit2 = StreamAuditEvent::now(AuditAction::RuleAdded, "rust lang");

        // Buffer events
        let mut buf = StreamBuffer::new(3, OverflowPolicy::DropOldest);
        for i in 0..5 {
            let mut e = make_event();
            e.tweet_id = format!("t{i}");
            buf.push(e);
        }

        let _audit3 = StreamAuditEvent::now(AuditAction::BufferOverflow, "dropped 2");
        assert_eq!(buf.status().dropped_total, 2);

        // Drain
        let events = buf.drain();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].tweet_id, "t2");

        // Release lease
        assert!(mgr.release("agent-a"));
        let _audit4 = StreamAuditEvent::now(AuditAction::LeaseReleased, "agent-a");
    }

    #[test]
    fn integration_rule_set_fill_and_validate() {
        let mut set = StreamRuleSet {
            rules: Vec::new(),
            max_rules: 3,
        };
        for i in 0..3 {
            set.add_rule(StreamRule {
                id: Some(format!("r{i}")),
                value: format!("keyword{i}"),
                tag: Some(format!("tag{i}")),
            })
            .unwrap();
        }
        assert!(set.validate().is_ok());
        assert_eq!(set.rule_count(), 3);

        // Remove middle rule
        assert!(set.remove_rule("r1"));
        assert_eq!(set.rule_count(), 2);

        // Can add one more now
        set.add_rule(StreamRule {
            id: Some("r3".into()),
            value: "new rule".into(),
            tag: None,
        })
        .unwrap();
        assert_eq!(set.rule_count(), 3);
    }

    #[test]
    fn integration_config_with_all_fields() {
        let cfg = StreamConfig {
            backfill_minutes: Some(5),
            tweet_fields: vec![
                TweetField::Id,
                TweetField::Text,
                TweetField::AuthorId,
                TweetField::CreatedAt,
                TweetField::Lang,
                TweetField::PublicMetrics,
            ],
            expansions: vec![Expansion::AuthorId, Expansion::ReferencedTweetsId],
            buffer_capacity: 2048,
            max_reconnect_attempts: 20,
        };
        assert!(cfg.validate().is_ok());

        // Verify field names
        assert_eq!(cfg.tweet_fields[0].as_str(), "id");
        assert_eq!(cfg.tweet_fields[5].as_str(), "public_metrics");
        assert_eq!(cfg.expansions[1].as_str(), "referenced_tweets.id");
    }

    #[test]
    fn integration_buffer_block_then_drain_then_push() {
        let mut buf = StreamBuffer::new(2, OverflowPolicy::Block);
        buf.push(make_event());
        buf.push(make_event());
        assert!(buf.is_backpressured());

        // Drain frees space
        let events = buf.drain();
        assert_eq!(events.len(), 2);
        assert!(!buf.is_backpressured());

        // Can push again
        assert!(buf.push(make_event()));
    }
}
