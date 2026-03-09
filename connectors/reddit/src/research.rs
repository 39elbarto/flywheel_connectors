//! `Reddit` Authentic User Opinions Research.
//!
//! Research-focused macro surface for extracting authentic user opinions.
//! Provides data acquisition and packaging for downstream agent reasoning.
//!
//! # Macros
//!
//! - **`search_threads`** — query + subreddit + time window to ranked summaries
//! - **`collect_evidence`** — thread ids to bounded comment excerpts with provenance

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ── Time window ─────────────────────────────────────────────────────────

/// Time window filter for `Reddit` thread searches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimeWindow {
    /// Past 24 hours.
    PastDay,
    /// Past 7 days.
    PastWeek,
    /// Past 30 days.
    PastMonth,
    /// Past 365 days.
    PastYear,
    /// All time (no time filter).
    All,
    /// Custom UTC timestamp range.
    Custom {
        /// Start timestamp (inclusive).
        after_utc: f64,
        /// End timestamp (exclusive).
        before_utc: f64,
    },
}

impl TimeWindow {
    /// Returns the `Reddit` API `t` filter parameter value.
    #[must_use]
    pub const fn as_filter(&self) -> &str {
        match self {
            Self::PastDay => "day",
            Self::PastWeek => "week",
            Self::PastMonth => "month",
            Self::PastYear => "year",
            Self::All | Self::Custom { .. } => "all",
        }
    }
}

// ── Sentiment ───────────────────────────────────────────────────────────

/// Simple sentiment signal derived from `Reddit` post score heuristics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SentimentSignal {
    /// Predominantly positive reception.
    Positive,
    /// Predominantly negative reception.
    Negative,
    /// Mixed or controversial reception.
    Mixed,
    /// Neutral or insufficient signal.
    Neutral,
}

impl SentimentSignal {
    /// Derive a sentiment signal from a post score using simple heuristics.
    ///
    /// - score >= 10 => Positive
    /// - score <= -5 => Negative
    /// - score between -5 and 0 (exclusive) => Mixed
    /// - score 0..10 => Neutral
    #[must_use]
    pub const fn from_score(score: i64) -> Self {
        if score >= 10 {
            Self::Positive
        } else if score <= -5 {
            Self::Negative
        } else if score < 0 {
            Self::Mixed
        } else {
            Self::Neutral
        }
    }
}

// ── Research query ──────────────────────────────────────────────────────

/// A research query for searching `Reddit` threads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchQuery {
    /// The search query string.
    pub query: String,
    /// Subreddits to search within (empty = all).
    pub subreddits: Vec<String>,
    /// Time window for the search.
    pub time_window: TimeWindow,
    /// Minimum post score filter.
    pub min_score: Option<i64>,
    /// Minimum comment count filter.
    pub min_comments: Option<u32>,
    /// Maximum number of threads to return (default 25, max 100).
    pub max_threads: u32,
}

impl ResearchQuery {
    /// Maximum allowed threads per query.
    pub const MAX_THREADS_LIMIT: u32 = 100;
    /// Default number of threads to return.
    pub const DEFAULT_MAX_THREADS: u32 = 25;

    /// Create a new research query with the given search string.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            subreddits: Vec::new(),
            time_window: TimeWindow::All,
            min_score: None,
            min_comments: None,
            max_threads: Self::DEFAULT_MAX_THREADS,
        }
    }

    /// Add a subreddit to search within.
    #[must_use]
    pub fn add_subreddit(mut self, subreddit: impl Into<String>) -> Self {
        self.subreddits.push(subreddit.into());
        self
    }

    /// Set the time window for the search.
    #[must_use]
    pub const fn with_time_window(mut self, tw: TimeWindow) -> Self {
        self.time_window = tw;
        self
    }

    /// Set the minimum post score filter.
    #[must_use]
    pub const fn with_min_score(mut self, score: i64) -> Self {
        self.min_score = Some(score);
        self
    }

    /// Set the minimum comment count filter.
    #[must_use]
    pub const fn with_min_comments(mut self, count: u32) -> Self {
        self.min_comments = Some(count);
        self
    }

    /// Set the maximum number of threads to return.
    ///
    /// Clamped to [`Self::MAX_THREADS_LIMIT`].
    #[must_use]
    pub fn with_max_threads(mut self, max: u32) -> Self {
        self.max_threads = max.min(Self::MAX_THREADS_LIMIT);
        self
    }

    /// Validate the query, returning an error message if invalid.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the query is empty, `max_threads` is zero,
    /// or a `Custom` time window has invalid bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.query.trim().is_empty() {
            return Err("query must not be empty".into());
        }
        if self.max_threads == 0 {
            return Err("max_threads must be at least 1".into());
        }
        if self.max_threads > Self::MAX_THREADS_LIMIT {
            return Err(format!(
                "max_threads must be at most {}",
                Self::MAX_THREADS_LIMIT
            ));
        }
        if let TimeWindow::Custom {
            after_utc,
            before_utc,
        } = &self.time_window
        {
            if after_utc >= before_utc {
                return Err("Custom time window: after_utc must be before before_utc".into());
            }
            if *after_utc < 0.0 {
                return Err("Custom time window: after_utc must be non-negative".into());
            }
        }
        Ok(())
    }
}

// ── Thread summary ──────────────────────────────────────────────────────

/// Summary of a `Reddit` thread returned from a search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSummary {
    /// The `Reddit` thread id (e.g. `t3_abc123`).
    pub thread_id: String,
    /// Post title.
    pub title: String,
    /// Subreddit name (without "r/" prefix).
    pub subreddit: String,
    /// Post author username.
    pub author: String,
    /// Post score (upvotes minus downvotes).
    pub score: i64,
    /// Number of comments on the thread.
    pub num_comments: u32,
    /// UTC timestamp of thread creation.
    pub created_utc: f64,
    /// Full URL to the thread.
    pub url: String,
    /// Rank in the search results (1-based).
    pub relevance_rank: u32,
    /// Optional sentiment signal based on score heuristics.
    pub sentiment_signal: Option<SentimentSignal>,
}

// ── Thread search results ───────────────────────────────────────────────

/// Results from a `Reddit` thread search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSearchResults {
    /// Matched threads, ordered by relevance.
    pub threads: Vec<ThreadSummary>,
    /// Echo of the original query string.
    pub query_echo: String,
    /// Total number of results found (if available from API).
    pub total_found: Option<u32>,
    /// Time window used for the search.
    pub time_window: TimeWindow,
}

impl ThreadSearchResults {
    /// Returns `true` if no threads were found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }

    /// Returns the number of threads in this result set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.threads.len()
    }
}

// ── Evidence request ────────────────────────────────────────────────────

/// Request to collect evidence (comment excerpts) from specific threads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRequest {
    /// Thread IDs to collect comments from.
    pub thread_ids: Vec<String>,
    /// Maximum comments to collect per thread (default 50, max 200).
    pub max_comments_per_thread: u32,
    /// Minimum comment score filter.
    pub min_score: Option<i64>,
    /// Whether to include controversial comments.
    pub include_controversial: bool,
    /// Maximum comment tree depth to traverse (default 5).
    pub max_depth: u32,
}

impl EvidenceRequest {
    /// Maximum allowed comments per thread.
    pub const MAX_COMMENTS_LIMIT: u32 = 200;
    /// Default comments per thread.
    pub const DEFAULT_MAX_COMMENTS: u32 = 50;
    /// Default max depth.
    pub const DEFAULT_MAX_DEPTH: u32 = 5;

    /// Create a new evidence request for the given thread IDs.
    #[must_use]
    pub const fn new(thread_ids: Vec<String>) -> Self {
        Self {
            thread_ids,
            max_comments_per_thread: Self::DEFAULT_MAX_COMMENTS,
            min_score: None,
            include_controversial: false,
            max_depth: Self::DEFAULT_MAX_DEPTH,
        }
    }

    /// Set the maximum number of comments per thread.
    ///
    /// Clamped to [`Self::MAX_COMMENTS_LIMIT`].
    #[must_use]
    pub fn with_max_comments(mut self, max: u32) -> Self {
        self.max_comments_per_thread = max.min(Self::MAX_COMMENTS_LIMIT);
        self
    }

    /// Set the minimum comment score filter.
    #[must_use]
    pub const fn with_min_score(mut self, score: i64) -> Self {
        self.min_score = Some(score);
        self
    }

    /// Include controversial comments in the results.
    #[must_use]
    pub const fn include_controversial(mut self) -> Self {
        self.include_controversial = true;
        self
    }

    /// Set the maximum comment tree depth.
    #[must_use]
    pub const fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    /// Validate the evidence request, returning an error message if invalid.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `thread_ids` is empty, `max_comments_per_thread` is
    /// zero, or `max_depth` is zero.
    pub fn validate(&self) -> Result<(), String> {
        if self.thread_ids.is_empty() {
            return Err("thread_ids must not be empty".into());
        }
        if self.max_comments_per_thread == 0 {
            return Err("max_comments_per_thread must be at least 1".into());
        }
        if self.max_comments_per_thread > Self::MAX_COMMENTS_LIMIT {
            return Err(format!(
                "max_comments_per_thread must be at most {}",
                Self::MAX_COMMENTS_LIMIT
            ));
        }
        if self.max_depth == 0 {
            return Err("max_depth must be at least 1".into());
        }
        // Check for duplicate thread IDs
        let mut seen = std::collections::HashSet::new();
        for tid in &self.thread_ids {
            if !seen.insert(tid.as_str()) {
                return Err(format!("duplicate thread_id: {tid}"));
            }
        }
        Ok(())
    }
}

// ── Evidence excerpt ────────────────────────────────────────────────────

/// A bounded excerpt from a `Reddit` comment with provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceExcerpt {
    /// The `Reddit` comment ID (e.g. `t1_xyz`).
    pub comment_id: String,
    /// Parent thread ID.
    pub thread_id: String,
    /// Comment author username.
    pub author: String,
    /// Truncated body text (max 2000 chars).
    pub body_excerpt: String,
    /// Comment score.
    pub score: i64,
    /// Depth in the comment tree (0 = top-level).
    pub depth: u32,
    /// Parent comment or thread ID.
    pub parent_id: Option<String>,
    /// Permalink to the comment.
    pub permalink: String,
    /// UTC timestamp of comment creation.
    pub created_utc: f64,
}

// ── Provenance pointer ──────────────────────────────────────────────────

/// Provenance pointer linking an excerpt back to its source on `Reddit`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenancePointer {
    /// Thread ID containing the comment.
    pub thread_id: String,
    /// Comment ID within the thread.
    pub comment_id: String,
    /// Subreddit name.
    pub subreddit: String,
    /// Permalink to the comment.
    pub permalink: String,
}

// ── Evidence collection ─────────────────────────────────────────────────

/// Collection of evidence excerpts from a single `Reddit` thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCollection {
    /// The thread these excerpts came from.
    pub thread_id: String,
    /// Collected excerpts.
    pub excerpts: Vec<EvidenceExcerpt>,
    /// Total comments available in the thread.
    pub total_available: u32,
    /// Number of comments actually collected.
    pub collected: u32,
    /// Whether the collection was truncated due to limits.
    pub truncated: bool,
}

impl EvidenceCollection {
    /// Returns `true` if no excerpts were collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.excerpts.is_empty()
    }

    /// Returns the number of collected excerpts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.excerpts.len()
    }
}

// ── Research results ────────────────────────────────────────────────────

/// Aggregated results from evidence collection across multiple threads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchResults {
    /// Per-thread evidence collections.
    pub collections: Vec<EvidenceCollection>,
    /// Total excerpts across all collections.
    pub total_excerpts: u32,
    /// Provenance pointers for all collected excerpts.
    pub provenance: Vec<ProvenancePointer>,
}

impl ResearchResults {
    /// Returns `true` if no evidence was collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.collections.is_empty()
    }

    /// Returns the number of collections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.collections.len()
    }
}

// ── Research bounds ─────────────────────────────────────────────────────

/// Safety bounds for `Reddit` research operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchBounds {
    /// Maximum threads per search query.
    pub max_threads: u32,
    /// Maximum comments per thread.
    pub max_comments_per_thread: u32,
    /// Maximum excerpt body length in characters.
    pub max_excerpt_length: usize,
    /// Maximum total excerpts across all threads.
    pub max_total_excerpts: u32,
}

impl Default for ResearchBounds {
    fn default() -> Self {
        Self {
            max_threads: 100,
            max_comments_per_thread: 200,
            max_excerpt_length: 2000,
            max_total_excerpts: 500,
        }
    }
}

impl ResearchBounds {
    /// Validate a [`ResearchQuery`] against these bounds.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the query exceeds any bound.
    pub fn validate_query(&self, query: &ResearchQuery) -> Result<(), String> {
        query.validate()?;
        if query.max_threads > self.max_threads {
            return Err(format!(
                "max_threads {} exceeds bound {}",
                query.max_threads, self.max_threads
            ));
        }
        Ok(())
    }

    /// Validate an [`EvidenceRequest`] against these bounds.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the request exceeds any bound.
    pub fn validate_evidence_request(&self, request: &EvidenceRequest) -> Result<(), String> {
        request.validate()?;
        if request.max_comments_per_thread > self.max_comments_per_thread {
            return Err(format!(
                "max_comments_per_thread {} exceeds bound {}",
                request.max_comments_per_thread, self.max_comments_per_thread
            ));
        }
        let potential_total =
            request.thread_ids.len() as u32 * request.max_comments_per_thread;
        if potential_total > self.max_total_excerpts {
            return Err(format!(
                "potential total excerpts {potential_total} exceeds bound {}",
                self.max_total_excerpts
            ));
        }
        Ok(())
    }

    /// Truncate an excerpt body to the configured maximum length.
    #[must_use]
    pub fn truncate_excerpt(&self, body: &str) -> String {
        let chars: Vec<char> = body.chars().collect();
        if chars.len() <= self.max_excerpt_length {
            body.to_owned()
        } else {
            let mut result: String = chars[..self.max_excerpt_length].iter().collect();
            result.push_str("...");
            result
        }
    }
}

// ── Research audit event ────────────────────────────────────────────────

/// Action type for research audit events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResearchAction {
    /// A thread search was performed.
    Search,
    /// Evidence collection was performed.
    Collect,
}

/// Audit event for research operations.
///
/// Note: the actual query text is never logged; only a hash is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchAuditEvent {
    /// Timestamp of the event (UTC seconds since epoch).
    pub timestamp: f64,
    /// Action type.
    pub action: ResearchAction,
    /// Hash of the query string (never the actual query).
    pub query_hash: Option<u64>,
    /// Number of threads involved.
    pub thread_count: u32,
    /// Number of excerpts collected.
    pub excerpt_count: u32,
}

impl ResearchAuditEvent {
    /// Create a search audit event.
    #[must_use]
    pub fn search(timestamp: f64, query: &str, thread_count: u32) -> Self {
        Self {
            timestamp,
            action: ResearchAction::Search,
            query_hash: Some(Self::hash_query(query)),
            thread_count,
            excerpt_count: 0,
        }
    }

    /// Create a collect audit event.
    #[must_use]
    pub const fn collect(timestamp: f64, thread_count: u32, excerpt_count: u32) -> Self {
        Self {
            timestamp,
            action: ResearchAction::Collect,
            query_hash: None,
            thread_count,
            excerpt_count,
        }
    }

    /// Hash a query string for audit purposes without revealing the content.
    fn hash_query(query: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        query.hash(&mut hasher);
        hasher.finish()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── TimeWindow ──────────────────────────────────────────────────

    #[test]
    fn time_window_past_day_filter() {
        assert_eq!(TimeWindow::PastDay.as_filter(), "day");
    }

    #[test]
    fn time_window_past_week_filter() {
        assert_eq!(TimeWindow::PastWeek.as_filter(), "week");
    }

    #[test]
    fn time_window_past_month_filter() {
        assert_eq!(TimeWindow::PastMonth.as_filter(), "month");
    }

    #[test]
    fn time_window_past_year_filter() {
        assert_eq!(TimeWindow::PastYear.as_filter(), "year");
    }

    #[test]
    fn time_window_all_filter() {
        assert_eq!(TimeWindow::All.as_filter(), "all");
    }

    #[test]
    fn time_window_custom_filter() {
        let tw = TimeWindow::Custom {
            after_utc: 1000.0,
            before_utc: 2000.0,
        };
        assert_eq!(tw.as_filter(), "all");
    }

    #[test]
    fn time_window_clone() {
        let tw = TimeWindow::PastWeek;
        #[allow(clippy::redundant_clone)]
        let tw2 = tw.clone();
        assert_eq!(tw2.as_filter(), "week");
    }

    #[test]
    fn time_window_debug() {
        let dbg = format!("{:?}", TimeWindow::PastDay);
        assert!(dbg.contains("PastDay"));
    }

    #[test]
    fn time_window_serialize_roundtrip() {
        let tw = TimeWindow::Custom {
            after_utc: 100.0,
            before_utc: 200.0,
        };
        let json = serde_json::to_value(&tw).unwrap();
        let tw2: TimeWindow = serde_json::from_value(json).unwrap();
        assert_eq!(tw, tw2);
    }

    #[test]
    fn time_window_all_serialize() {
        let v = serde_json::to_value(&TimeWindow::All).unwrap();
        let tw: TimeWindow = serde_json::from_value(v).unwrap();
        assert_eq!(tw, TimeWindow::All);
    }

    #[test]
    fn time_window_partial_eq() {
        assert_eq!(TimeWindow::PastDay, TimeWindow::PastDay);
        assert_ne!(TimeWindow::PastDay, TimeWindow::PastWeek);
    }

    // ── SentimentSignal ─────────────────────────────────────────────

    #[test]
    fn sentiment_positive_high_score() {
        assert_eq!(SentimentSignal::from_score(100), SentimentSignal::Positive);
    }

    #[test]
    fn sentiment_positive_threshold() {
        assert_eq!(SentimentSignal::from_score(10), SentimentSignal::Positive);
    }

    #[test]
    fn sentiment_neutral_below_threshold() {
        assert_eq!(SentimentSignal::from_score(9), SentimentSignal::Neutral);
    }

    #[test]
    fn sentiment_neutral_zero() {
        assert_eq!(SentimentSignal::from_score(0), SentimentSignal::Neutral);
    }

    #[test]
    fn sentiment_mixed_negative() {
        assert_eq!(SentimentSignal::from_score(-1), SentimentSignal::Mixed);
    }

    #[test]
    fn sentiment_mixed_boundary() {
        assert_eq!(SentimentSignal::from_score(-4), SentimentSignal::Mixed);
    }

    #[test]
    fn sentiment_negative_threshold() {
        assert_eq!(SentimentSignal::from_score(-5), SentimentSignal::Negative);
    }

    #[test]
    fn sentiment_negative_deep() {
        assert_eq!(SentimentSignal::from_score(-100), SentimentSignal::Negative);
    }

    #[test]
    fn sentiment_clone() {
        let s = SentimentSignal::Positive;
        let s2 = s;
        assert_eq!(s2, SentimentSignal::Positive);
    }

    #[test]
    fn sentiment_debug() {
        let dbg = format!("{:?}", SentimentSignal::Mixed);
        assert!(dbg.contains("Mixed"));
    }

    #[test]
    fn sentiment_serialize_roundtrip() {
        let s = SentimentSignal::Negative;
        let v = serde_json::to_value(s).unwrap();
        let s2: SentimentSignal = serde_json::from_value(v).unwrap();
        assert_eq!(s2, SentimentSignal::Negative);
    }

    #[test]
    fn sentiment_copy() {
        let s = SentimentSignal::Neutral;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── ResearchQuery ───────────────────────────────────────────────

    #[test]
    fn research_query_new_defaults() {
        let q = ResearchQuery::new("rust async");
        assert_eq!(q.query, "rust async");
        assert!(q.subreddits.is_empty());
        assert_eq!(q.time_window, TimeWindow::All);
        assert!(q.min_score.is_none());
        assert!(q.min_comments.is_none());
        assert_eq!(q.max_threads, 25);
    }

    #[test]
    fn research_query_builder_chain() {
        let q = ResearchQuery::new("tokio")
            .add_subreddit("rust")
            .add_subreddit("programming")
            .with_time_window(TimeWindow::PastMonth)
            .with_min_score(5)
            .with_min_comments(3)
            .with_max_threads(50);
        assert_eq!(q.subreddits.len(), 2);
        assert_eq!(q.time_window, TimeWindow::PastMonth);
        assert_eq!(q.min_score, Some(5));
        assert_eq!(q.min_comments, Some(3));
        assert_eq!(q.max_threads, 50);
    }

    #[test]
    fn research_query_max_threads_clamped() {
        let q = ResearchQuery::new("test").with_max_threads(999);
        assert_eq!(q.max_threads, 100);
    }

    #[test]
    fn research_query_max_threads_at_limit() {
        let q = ResearchQuery::new("test").with_max_threads(100);
        assert_eq!(q.max_threads, 100);
    }

    #[test]
    fn research_query_validate_ok() {
        let q = ResearchQuery::new("valid query");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn research_query_validate_empty_query() {
        let q = ResearchQuery::new("");
        assert!(q.validate().is_err());
        assert!(q.validate().unwrap_err().contains("empty"));
    }

    #[test]
    fn research_query_validate_whitespace_query() {
        let q = ResearchQuery::new("   ");
        assert!(q.validate().is_err());
    }

    #[test]
    fn research_query_validate_zero_threads() {
        let mut q = ResearchQuery::new("test");
        q.max_threads = 0;
        assert!(q.validate().is_err());
        assert!(q.validate().unwrap_err().contains("at least 1"));
    }

    #[test]
    fn research_query_validate_over_max_threads() {
        let mut q = ResearchQuery::new("test");
        q.max_threads = 101;
        assert!(q.validate().is_err());
        assert!(q.validate().unwrap_err().contains("at most 100"));
    }

    #[test]
    fn research_query_validate_custom_time_invalid() {
        let q = ResearchQuery::new("test")
            .with_time_window(TimeWindow::Custom {
                after_utc: 2000.0,
                before_utc: 1000.0,
            });
        assert!(q.validate().is_err());
        assert!(q.validate().unwrap_err().contains("before"));
    }

    #[test]
    fn research_query_validate_custom_time_equal() {
        let q = ResearchQuery::new("test")
            .with_time_window(TimeWindow::Custom {
                after_utc: 1000.0,
                before_utc: 1000.0,
            });
        assert!(q.validate().is_err());
    }

    #[test]
    fn research_query_validate_custom_time_negative() {
        let q = ResearchQuery::new("test")
            .with_time_window(TimeWindow::Custom {
                after_utc: -1.0,
                before_utc: 1000.0,
            });
        assert!(q.validate().is_err());
        assert!(q.validate().unwrap_err().contains("non-negative"));
    }

    #[test]
    fn research_query_validate_custom_time_valid() {
        let q = ResearchQuery::new("test")
            .with_time_window(TimeWindow::Custom {
                after_utc: 100.0,
                before_utc: 200.0,
            });
        assert!(q.validate().is_ok());
    }

    #[test]
    fn research_query_clone() {
        let q = ResearchQuery::new("clone test").add_subreddit("rust");
        #[allow(clippy::redundant_clone)]
        let q2 = q.clone();
        assert_eq!(q2.query, "clone test");
        assert_eq!(q2.subreddits.len(), 1);
    }

    #[test]
    fn research_query_debug() {
        let q = ResearchQuery::new("debug test");
        let dbg = format!("{q:?}");
        assert!(dbg.contains("debug test"));
    }

    #[test]
    fn research_query_serialize_roundtrip() {
        let q = ResearchQuery::new("serde").add_subreddit("rust").with_min_score(10);
        let v = serde_json::to_value(&q).unwrap();
        let q2: ResearchQuery = serde_json::from_value(v).unwrap();
        assert_eq!(q2.query, "serde");
        assert_eq!(q2.subreddits, vec!["rust"]);
        assert_eq!(q2.min_score, Some(10));
    }

    #[test]
    fn research_query_multiple_subreddits() {
        let q = ResearchQuery::new("test")
            .add_subreddit("rust")
            .add_subreddit("golang")
            .add_subreddit("python");
        assert_eq!(q.subreddits.len(), 3);
        assert_eq!(q.subreddits[2], "python");
    }

    // ── ThreadSummary ───────────────────────────────────────────────

    #[test]
    fn thread_summary_serialize_roundtrip() {
        let ts = ThreadSummary {
            thread_id: "t3_abc".into(),
            title: "Test Thread".into(),
            subreddit: "rust".into(),
            author: "user1".into(),
            score: 42,
            num_comments: 10,
            created_utc: 1_700_000_000.0,
            url: "https://reddit.com/r/rust/comments/abc/test/".into(),
            relevance_rank: 1,
            sentiment_signal: Some(SentimentSignal::Positive),
        };
        let v = serde_json::to_value(&ts).unwrap();
        assert_eq!(v["thread_id"], "t3_abc");
        assert_eq!(v["score"], 42);
        let ts2: ThreadSummary = serde_json::from_value(v).unwrap();
        assert_eq!(ts2.thread_id, "t3_abc");
    }

    #[test]
    fn thread_summary_clone() {
        let ts = ThreadSummary {
            thread_id: "t3_cl".into(),
            title: "Clone".into(),
            subreddit: "test".into(),
            author: "a".into(),
            score: 1,
            num_comments: 0,
            created_utc: 0.0,
            url: String::new(),
            relevance_rank: 1,
            sentiment_signal: None,
        };
        #[allow(clippy::redundant_clone)]
        let ts2 = ts.clone();
        assert_eq!(ts2.thread_id, "t3_cl");
    }

    #[test]
    fn thread_summary_debug() {
        let ts = ThreadSummary {
            thread_id: "t3_dbg".into(),
            title: "Debug".into(),
            subreddit: "test".into(),
            author: "a".into(),
            score: 0,
            num_comments: 0,
            created_utc: 0.0,
            url: String::new(),
            relevance_rank: 1,
            sentiment_signal: None,
        };
        let dbg = format!("{ts:?}");
        assert!(dbg.contains("t3_dbg"));
    }

    #[test]
    fn thread_summary_negative_score() {
        let ts = ThreadSummary {
            thread_id: "t3_neg".into(),
            title: "Neg".into(),
            subreddit: "test".into(),
            author: "a".into(),
            score: -50,
            num_comments: 100,
            created_utc: 0.0,
            url: String::new(),
            relevance_rank: 1,
            sentiment_signal: Some(SentimentSignal::Negative),
        };
        assert_eq!(ts.score, -50);
        assert_eq!(ts.sentiment_signal, Some(SentimentSignal::Negative));
    }

    #[test]
    fn thread_summary_no_sentiment() {
        let ts = ThreadSummary {
            thread_id: "t3_no".into(),
            title: "No".into(),
            subreddit: "test".into(),
            author: "a".into(),
            score: 0,
            num_comments: 0,
            created_utc: 0.0,
            url: String::new(),
            relevance_rank: 1,
            sentiment_signal: None,
        };
        assert!(ts.sentiment_signal.is_none());
    }

    // ── ThreadSearchResults ─────────────────────────────────────────

    #[test]
    fn thread_search_results_empty() {
        let r = ThreadSearchResults {
            threads: vec![],
            query_echo: "test".into(),
            total_found: None,
            time_window: TimeWindow::All,
        };
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn thread_search_results_non_empty() {
        let ts = ThreadSummary {
            thread_id: "t3_x".into(),
            title: "T".into(),
            subreddit: "s".into(),
            author: "a".into(),
            score: 1,
            num_comments: 0,
            created_utc: 0.0,
            url: String::new(),
            relevance_rank: 1,
            sentiment_signal: None,
        };
        let r = ThreadSearchResults {
            threads: vec![ts],
            query_echo: "test".into(),
            total_found: Some(1),
            time_window: TimeWindow::PastDay,
        };
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);
        assert_eq!(r.total_found, Some(1));
    }

    #[test]
    fn thread_search_results_clone() {
        let r = ThreadSearchResults {
            threads: vec![],
            query_echo: "q".into(),
            total_found: None,
            time_window: TimeWindow::PastWeek,
        };
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert_eq!(r2.query_echo, "q");
    }

    #[test]
    fn thread_search_results_debug() {
        let r = ThreadSearchResults {
            threads: vec![],
            query_echo: "dbg".into(),
            total_found: None,
            time_window: TimeWindow::All,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("dbg"));
    }

    #[test]
    fn thread_search_results_serialize() {
        let r = ThreadSearchResults {
            threads: vec![],
            query_echo: "ser".into(),
            total_found: Some(42),
            time_window: TimeWindow::PastMonth,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["query_echo"], "ser");
        assert_eq!(v["total_found"], 42);
    }

    // ── EvidenceRequest ─────────────────────────────────────────────

    #[test]
    fn evidence_request_new_defaults() {
        let r = EvidenceRequest::new(vec!["t3_a".into()]);
        assert_eq!(r.thread_ids.len(), 1);
        assert_eq!(r.max_comments_per_thread, 50);
        assert!(r.min_score.is_none());
        assert!(!r.include_controversial);
        assert_eq!(r.max_depth, 5);
    }

    #[test]
    fn evidence_request_builder_chain() {
        let r = EvidenceRequest::new(vec!["t3_a".into()])
            .with_max_comments(100)
            .with_min_score(5)
            .include_controversial()
            .with_max_depth(10);
        assert_eq!(r.max_comments_per_thread, 100);
        assert_eq!(r.min_score, Some(5));
        assert!(r.include_controversial);
        assert_eq!(r.max_depth, 10);
    }

    #[test]
    fn evidence_request_max_comments_clamped() {
        let r = EvidenceRequest::new(vec!["t3_a".into()]).with_max_comments(999);
        assert_eq!(r.max_comments_per_thread, 200);
    }

    #[test]
    fn evidence_request_validate_ok() {
        let r = EvidenceRequest::new(vec!["t3_a".into()]);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn evidence_request_validate_empty_ids() {
        let r = EvidenceRequest::new(vec![]);
        assert!(r.validate().is_err());
        assert!(r.validate().unwrap_err().contains("empty"));
    }

    #[test]
    fn evidence_request_validate_zero_comments() {
        let mut r = EvidenceRequest::new(vec!["t3_a".into()]);
        r.max_comments_per_thread = 0;
        assert!(r.validate().is_err());
    }

    #[test]
    fn evidence_request_validate_over_max_comments() {
        let mut r = EvidenceRequest::new(vec!["t3_a".into()]);
        r.max_comments_per_thread = 201;
        assert!(r.validate().is_err());
    }

    #[test]
    fn evidence_request_validate_zero_depth() {
        let mut r = EvidenceRequest::new(vec!["t3_a".into()]);
        r.max_depth = 0;
        assert!(r.validate().is_err());
        assert!(r.validate().unwrap_err().contains("depth"));
    }

    #[test]
    fn evidence_request_validate_duplicate_ids() {
        let r = EvidenceRequest::new(vec!["t3_a".into(), "t3_a".into()]);
        assert!(r.validate().is_err());
        assert!(r.validate().unwrap_err().contains("duplicate"));
    }

    #[test]
    fn evidence_request_clone() {
        let r = EvidenceRequest::new(vec!["t3_x".into()]);
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert_eq!(r2.thread_ids, vec!["t3_x"]);
    }

    #[test]
    fn evidence_request_debug() {
        let r = EvidenceRequest::new(vec!["t3_dbg".into()]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("t3_dbg"));
    }

    #[test]
    fn evidence_request_serialize_roundtrip() {
        let r = EvidenceRequest::new(vec!["t3_ser".into()])
            .with_max_comments(75)
            .with_min_score(-3)
            .include_controversial();
        let v = serde_json::to_value(&r).unwrap();
        let r2: EvidenceRequest = serde_json::from_value(v).unwrap();
        assert_eq!(r2.thread_ids, vec!["t3_ser"]);
        assert_eq!(r2.max_comments_per_thread, 75);
        assert_eq!(r2.min_score, Some(-3));
        assert!(r2.include_controversial);
    }

    #[test]
    fn evidence_request_multiple_ids() {
        let r = EvidenceRequest::new(vec!["t3_a".into(), "t3_b".into(), "t3_c".into()]);
        assert!(r.validate().is_ok());
        assert_eq!(r.thread_ids.len(), 3);
    }

    // ── EvidenceExcerpt ─────────────────────────────────────────────

    #[test]
    fn evidence_excerpt_serialize_roundtrip() {
        let e = EvidenceExcerpt {
            comment_id: "t1_abc".into(),
            thread_id: "t3_xyz".into(),
            author: "user".into(),
            body_excerpt: "This is great!".into(),
            score: 25,
            depth: 0,
            parent_id: None,
            permalink: "/r/rust/comments/xyz/test/abc".into(),
            created_utc: 1_700_000_100.0,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["comment_id"], "t1_abc");
        assert_eq!(v["score"], 25);
        let e2: EvidenceExcerpt = serde_json::from_value(v).unwrap();
        assert_eq!(e2.comment_id, "t1_abc");
        assert_eq!(e2.depth, 0);
    }

    #[test]
    fn evidence_excerpt_with_parent() {
        let e = EvidenceExcerpt {
            comment_id: "t1_child".into(),
            thread_id: "t3_parent".into(),
            author: "replier".into(),
            body_excerpt: "I agree".into(),
            score: 5,
            depth: 2,
            parent_id: Some("t1_parent".into()),
            permalink: "/r/test/abc".into(),
            created_utc: 0.0,
        };
        assert_eq!(e.parent_id.as_deref(), Some("t1_parent"));
        assert_eq!(e.depth, 2);
    }

    #[test]
    fn evidence_excerpt_clone() {
        let e = EvidenceExcerpt {
            comment_id: "t1_cl".into(),
            thread_id: "t3_cl".into(),
            author: "a".into(),
            body_excerpt: "b".into(),
            score: 0,
            depth: 0,
            parent_id: None,
            permalink: String::new(),
            created_utc: 0.0,
        };
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.comment_id, "t1_cl");
    }

    #[test]
    fn evidence_excerpt_debug() {
        let e = EvidenceExcerpt {
            comment_id: "t1_dbg".into(),
            thread_id: "t3_dbg".into(),
            author: "a".into(),
            body_excerpt: "b".into(),
            score: 0,
            depth: 0,
            parent_id: None,
            permalink: String::new(),
            created_utc: 0.0,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("t1_dbg"));
    }

    #[test]
    fn evidence_excerpt_negative_score() {
        let e = EvidenceExcerpt {
            comment_id: "t1_neg".into(),
            thread_id: "t3_neg".into(),
            author: "a".into(),
            body_excerpt: "unpopular opinion".into(),
            score: -20,
            depth: 1,
            parent_id: Some("t3_neg".into()),
            permalink: String::new(),
            created_utc: 0.0,
        };
        assert_eq!(e.score, -20);
    }

    // ── ProvenancePointer ───────────────────────────────────────────

    #[test]
    fn provenance_pointer_serialize_roundtrip() {
        let p = ProvenancePointer {
            thread_id: "t3_abc".into(),
            comment_id: "t1_xyz".into(),
            subreddit: "rust".into(),
            permalink: "/r/rust/comments/abc/test/xyz".into(),
        };
        let v = serde_json::to_value(&p).unwrap();
        let p2: ProvenancePointer = serde_json::from_value(v).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn provenance_pointer_clone() {
        let p = ProvenancePointer {
            thread_id: "t3_cl".into(),
            comment_id: "t1_cl".into(),
            subreddit: "s".into(),
            permalink: String::new(),
        };
        #[allow(clippy::redundant_clone)]
        let p2 = p.clone();
        assert_eq!(p, p2);
    }

    #[test]
    fn provenance_pointer_debug() {
        let p = ProvenancePointer {
            thread_id: "t3_dbg".into(),
            comment_id: "t1_dbg".into(),
            subreddit: "test".into(),
            permalink: String::new(),
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("t3_dbg"));
    }

    #[test]
    fn provenance_pointer_eq() {
        let p1 = ProvenancePointer {
            thread_id: "t3_a".into(),
            comment_id: "t1_b".into(),
            subreddit: "s".into(),
            permalink: "p".into(),
        };
        let p2 = ProvenancePointer {
            thread_id: "t3_a".into(),
            comment_id: "t1_b".into(),
            subreddit: "s".into(),
            permalink: "p".into(),
        };
        assert_eq!(p1, p2);
    }

    #[test]
    fn provenance_pointer_ne() {
        let p1 = ProvenancePointer {
            thread_id: "t3_a".into(),
            comment_id: "t1_x".into(),
            subreddit: "s".into(),
            permalink: String::new(),
        };
        let p2 = ProvenancePointer {
            thread_id: "t3_a".into(),
            comment_id: "t1_y".into(),
            subreddit: "s".into(),
            permalink: String::new(),
        };
        assert_ne!(p1, p2);
    }

    // ── EvidenceCollection ──────────────────────────────────────────

    #[test]
    fn evidence_collection_empty() {
        let c = EvidenceCollection {
            thread_id: "t3_empty".into(),
            excerpts: vec![],
            total_available: 0,
            collected: 0,
            truncated: false,
        };
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert!(!c.truncated);
    }

    #[test]
    fn evidence_collection_non_empty() {
        let excerpt = EvidenceExcerpt {
            comment_id: "t1_a".into(),
            thread_id: "t3_a".into(),
            author: "a".into(),
            body_excerpt: "b".into(),
            score: 0,
            depth: 0,
            parent_id: None,
            permalink: String::new(),
            created_utc: 0.0,
        };
        let c = EvidenceCollection {
            thread_id: "t3_a".into(),
            excerpts: vec![excerpt],
            total_available: 50,
            collected: 1,
            truncated: true,
        };
        assert!(!c.is_empty());
        assert_eq!(c.len(), 1);
        assert!(c.truncated);
    }

    #[test]
    fn evidence_collection_clone() {
        let c = EvidenceCollection {
            thread_id: "t3_cl".into(),
            excerpts: vec![],
            total_available: 0,
            collected: 0,
            truncated: false,
        };
        #[allow(clippy::redundant_clone)]
        let c2 = c.clone();
        assert_eq!(c2.thread_id, "t3_cl");
    }

    #[test]
    fn evidence_collection_debug() {
        let c = EvidenceCollection {
            thread_id: "t3_dbg".into(),
            excerpts: vec![],
            total_available: 0,
            collected: 0,
            truncated: false,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("t3_dbg"));
    }

    #[test]
    fn evidence_collection_serialize() {
        let c = EvidenceCollection {
            thread_id: "t3_ser".into(),
            excerpts: vec![],
            total_available: 100,
            collected: 50,
            truncated: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["total_available"], 100);
        assert_eq!(v["collected"], 50);
        assert_eq!(v["truncated"], true);
    }

    // ── ResearchResults ─────────────────────────────────────────────

    #[test]
    fn research_results_empty() {
        let r = ResearchResults {
            collections: vec![],
            total_excerpts: 0,
            provenance: vec![],
        };
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.total_excerpts, 0);
    }

    #[test]
    fn research_results_non_empty() {
        let c = EvidenceCollection {
            thread_id: "t3_a".into(),
            excerpts: vec![],
            total_available: 0,
            collected: 0,
            truncated: false,
        };
        let p = ProvenancePointer {
            thread_id: "t3_a".into(),
            comment_id: "t1_a".into(),
            subreddit: "s".into(),
            permalink: String::new(),
        };
        let r = ResearchResults {
            collections: vec![c],
            total_excerpts: 5,
            provenance: vec![p],
        };
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);
        assert_eq!(r.total_excerpts, 5);
        assert_eq!(r.provenance.len(), 1);
    }

    #[test]
    fn research_results_clone() {
        let r = ResearchResults {
            collections: vec![],
            total_excerpts: 0,
            provenance: vec![],
        };
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert!(r2.is_empty());
    }

    #[test]
    fn research_results_debug() {
        let r = ResearchResults {
            collections: vec![],
            total_excerpts: 0,
            provenance: vec![],
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ResearchResults"));
    }

    #[test]
    fn research_results_serialize() {
        let r = ResearchResults {
            collections: vec![],
            total_excerpts: 42,
            provenance: vec![],
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["total_excerpts"], 42);
        let r2: ResearchResults = serde_json::from_value(v).unwrap();
        assert_eq!(r2.total_excerpts, 42);
    }

    // ── ResearchBounds ──────────────────────────────────────────────

    #[test]
    fn research_bounds_default() {
        let b = ResearchBounds::default();
        assert_eq!(b.max_threads, 100);
        assert_eq!(b.max_comments_per_thread, 200);
        assert_eq!(b.max_excerpt_length, 2000);
        assert_eq!(b.max_total_excerpts, 500);
    }

    #[test]
    fn research_bounds_validate_query_ok() {
        let b = ResearchBounds::default();
        let q = ResearchQuery::new("test");
        assert!(b.validate_query(&q).is_ok());
    }

    #[test]
    fn research_bounds_validate_query_over_max() {
        let b = ResearchBounds {
            max_threads: 10,
            ..ResearchBounds::default()
        };
        let q = ResearchQuery::new("test").with_max_threads(20);
        assert!(b.validate_query(&q).is_err());
        assert!(b.validate_query(&q).unwrap_err().contains("exceeds"));
    }

    #[test]
    fn research_bounds_validate_query_invalid() {
        let b = ResearchBounds::default();
        let q = ResearchQuery::new("");
        assert!(b.validate_query(&q).is_err());
    }

    #[test]
    fn research_bounds_validate_evidence_ok() {
        let b = ResearchBounds::default();
        let r = EvidenceRequest::new(vec!["t3_a".into()]);
        assert!(b.validate_evidence_request(&r).is_ok());
    }

    #[test]
    fn research_bounds_validate_evidence_over_comments() {
        let b = ResearchBounds {
            max_comments_per_thread: 50,
            ..ResearchBounds::default()
        };
        let mut r = EvidenceRequest::new(vec!["t3_a".into()]);
        r.max_comments_per_thread = 100;
        assert!(b.validate_evidence_request(&r).is_err());
        assert!(b
            .validate_evidence_request(&r)
            .unwrap_err()
            .contains("exceeds"));
    }

    #[test]
    fn research_bounds_validate_evidence_over_total() {
        let b = ResearchBounds {
            max_total_excerpts: 100,
            ..ResearchBounds::default()
        };
        // 3 threads * 50 comments = 150 > 100
        let r = EvidenceRequest::new(vec!["t3_a".into(), "t3_b".into(), "t3_c".into()]);
        assert!(b.validate_evidence_request(&r).is_err());
        assert!(b
            .validate_evidence_request(&r)
            .unwrap_err()
            .contains("total"));
    }

    #[test]
    fn research_bounds_validate_evidence_invalid() {
        let b = ResearchBounds::default();
        let r = EvidenceRequest::new(vec![]);
        assert!(b.validate_evidence_request(&r).is_err());
    }

    #[test]
    fn research_bounds_truncate_short() {
        let b = ResearchBounds::default();
        let result = b.truncate_excerpt("hello");
        assert_eq!(result, "hello");
    }

    #[test]
    fn research_bounds_truncate_exact_limit() {
        let b = ResearchBounds {
            max_excerpt_length: 5,
            ..ResearchBounds::default()
        };
        let result = b.truncate_excerpt("hello");
        assert_eq!(result, "hello");
    }

    #[test]
    fn research_bounds_truncate_over_limit() {
        let b = ResearchBounds {
            max_excerpt_length: 5,
            ..ResearchBounds::default()
        };
        let result = b.truncate_excerpt("hello world");
        assert_eq!(result, "hello...");
    }

    #[test]
    fn research_bounds_truncate_unicode() {
        let b = ResearchBounds {
            max_excerpt_length: 3,
            ..ResearchBounds::default()
        };
        // Multi-byte characters should be handled correctly
        let result = b.truncate_excerpt("\u{1F600}\u{1F601}\u{1F602}\u{1F603}");
        assert_eq!(
            result,
            "\u{1F600}\u{1F601}\u{1F602}..."
        );
    }

    #[test]
    fn research_bounds_truncate_empty() {
        let b = ResearchBounds::default();
        let result = b.truncate_excerpt("");
        assert_eq!(result, "");
    }

    #[test]
    fn research_bounds_clone() {
        let b = ResearchBounds {
            max_threads: 42,
            ..ResearchBounds::default()
        };
        #[allow(clippy::redundant_clone)]
        let b2 = b.clone();
        assert_eq!(b2.max_threads, 42);
    }

    #[test]
    fn research_bounds_debug() {
        let b = ResearchBounds::default();
        let dbg = format!("{b:?}");
        assert!(dbg.contains("ResearchBounds"));
    }

    #[test]
    fn research_bounds_serialize() {
        let b = ResearchBounds::default();
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["max_threads"], 100);
        assert_eq!(v["max_excerpt_length"], 2000);
    }

    // ── ResearchAuditEvent ──────────────────────────────────────────

    #[test]
    fn audit_event_search() {
        let e = ResearchAuditEvent::search(1_700_000_000.0, "rust async", 10);
        assert_eq!(e.action, ResearchAction::Search);
        assert!(e.query_hash.is_some());
        assert_eq!(e.thread_count, 10);
        assert_eq!(e.excerpt_count, 0);
        assert!((e.timestamp - 1_700_000_000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn audit_event_collect() {
        let e = ResearchAuditEvent::collect(1_700_000_000.0, 5, 150);
        assert_eq!(e.action, ResearchAction::Collect);
        assert!(e.query_hash.is_none());
        assert_eq!(e.thread_count, 5);
        assert_eq!(e.excerpt_count, 150);
    }

    #[test]
    fn audit_event_search_hash_deterministic() {
        let e1 = ResearchAuditEvent::search(0.0, "same query", 0);
        let e2 = ResearchAuditEvent::search(0.0, "same query", 0);
        assert_eq!(e1.query_hash, e2.query_hash);
    }

    #[test]
    fn audit_event_search_hash_differs() {
        let e1 = ResearchAuditEvent::search(0.0, "query one", 0);
        let e2 = ResearchAuditEvent::search(0.0, "query two", 0);
        assert_ne!(e1.query_hash, e2.query_hash);
    }

    #[test]
    fn audit_event_clone() {
        let e = ResearchAuditEvent::search(0.0, "clone test", 1);
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.action, ResearchAction::Search);
    }

    #[test]
    fn audit_event_debug() {
        let e = ResearchAuditEvent::collect(0.0, 3, 99);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Collect"));
    }

    #[test]
    fn audit_event_serialize_roundtrip() {
        let e = ResearchAuditEvent::search(12345.0, "ser test", 7);
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["thread_count"], 7);
        let e2: ResearchAuditEvent = serde_json::from_value(v).unwrap();
        assert_eq!(e2.thread_count, 7);
    }

    #[test]
    fn audit_event_action_eq() {
        assert_eq!(ResearchAction::Search, ResearchAction::Search);
        assert_ne!(ResearchAction::Search, ResearchAction::Collect);
    }

    #[test]
    fn audit_event_action_copy() {
        let a = ResearchAction::Collect;
        let a2 = a;
        assert_eq!(a, a2);
    }

    #[test]
    fn audit_event_action_serialize() {
        let v = serde_json::to_value(ResearchAction::Search).unwrap();
        let a: ResearchAction = serde_json::from_value(v).unwrap();
        assert_eq!(a, ResearchAction::Search);
    }

    // ── Integration-style tests ─────────────────────────────────────

    #[test]
    fn full_search_workflow() {
        // Build a query
        let q = ResearchQuery::new("best rust web framework")
            .add_subreddit("rust")
            .with_time_window(TimeWindow::PastMonth)
            .with_min_score(5)
            .with_max_threads(10);
        assert!(q.validate().is_ok());

        // Simulate search results
        let threads: Vec<ThreadSummary> = (0_u32..5)
            .map(|i| ThreadSummary {
                thread_id: format!("t3_{i}"),
                title: format!("Thread {i}"),
                subreddit: "rust".into(),
                author: format!("user{i}"),
                score: i64::from((i + 1) * 10),
                num_comments: (i + 1) * 5,
                created_utc: f64::from(i).mul_add(3600.0, 1_700_000_000.0),
                url: format!("https://reddit.com/r/rust/comments/t3_{i}/thread_{i}/"),
                relevance_rank: i + 1,
                sentiment_signal: Some(SentimentSignal::from_score(i64::from((i + 1) * 10))),
            })
            .collect();

        let results = ThreadSearchResults {
            threads,
            query_echo: q.query.clone(),
            total_found: Some(5),
            time_window: q.time_window.clone(),
        };
        assert_eq!(results.len(), 5);
        assert!(!results.is_empty());

        // Audit event
        let audit = ResearchAuditEvent::search(1_700_000_000.0, &q.query, results.len() as u32);
        assert_eq!(audit.thread_count, 5);
    }

    #[test]
    fn full_evidence_workflow() {
        let bounds = ResearchBounds::default();

        // Build evidence request
        let req = EvidenceRequest::new(vec!["t3_a".into(), "t3_b".into()])
            .with_max_comments(30)
            .with_min_score(2)
            .with_max_depth(3);
        assert!(bounds.validate_evidence_request(&req).is_ok());

        // Simulate collected evidence
        let excerpts: Vec<EvidenceExcerpt> = (0_u32..5)
            .map(|i| EvidenceExcerpt {
                comment_id: format!("t1_{i}"),
                thread_id: "t3_a".into(),
                author: format!("commenter{i}"),
                body_excerpt: bounds.truncate_excerpt(&format!("Comment body {i}")),
                score: i64::from(i * 3),
                depth: i % 3,
                parent_id: if i == 0 {
                    None
                } else {
                    Some(format!("t1_{}", i - 1))
                },
                permalink: format!("/r/rust/comments/t3_a/thread/t1_{i}"),
                created_utc: f64::from(i).mul_add(60.0, 1_700_000_100.0),
            })
            .collect();

        let provenance: Vec<ProvenancePointer> = excerpts
            .iter()
            .map(|e| ProvenancePointer {
                thread_id: e.thread_id.clone(),
                comment_id: e.comment_id.clone(),
                subreddit: "rust".into(),
                permalink: e.permalink.clone(),
            })
            .collect();

        let collection = EvidenceCollection {
            thread_id: "t3_a".into(),
            excerpts,
            total_available: 50,
            collected: 5,
            truncated: true,
        };

        let results = ResearchResults {
            collections: vec![collection],
            total_excerpts: 5,
            provenance,
        };
        assert_eq!(results.len(), 1);
        assert_eq!(results.total_excerpts, 5);
        assert_eq!(results.provenance.len(), 5);

        // Audit
        let audit = ResearchAuditEvent::collect(1_700_001_000.0, 1, 5);
        assert_eq!(audit.excerpt_count, 5);
    }

    #[test]
    fn bounds_enforce_on_query() {
        let bounds = ResearchBounds {
            max_threads: 10,
            ..ResearchBounds::default()
        };
        let q = ResearchQuery::new("test").with_max_threads(10);
        assert!(bounds.validate_query(&q).is_ok());

        let q_over = ResearchQuery::new("test").with_max_threads(11);
        // with_max_threads clamps to 100, so 11 is valid for ResearchQuery itself
        // but bounds check will still fail since 11 > 10
        assert!(bounds.validate_query(&q_over).is_err());
    }

    #[test]
    fn bounds_enforce_on_evidence() {
        let bounds = ResearchBounds {
            max_comments_per_thread: 25,
            max_total_excerpts: 50,
            ..ResearchBounds::default()
        };
        let r = EvidenceRequest::new(vec!["t3_a".into()]).with_max_comments(25);
        assert!(bounds.validate_evidence_request(&r).is_ok());

        // 3 threads * 25 = 75 > 50
        let r_over = EvidenceRequest::new(vec!["t3_a".into(), "t3_b".into(), "t3_c".into()])
            .with_max_comments(25);
        assert!(bounds.validate_evidence_request(&r_over).is_err());
    }

    #[test]
    fn thread_summary_from_json() {
        let v = json!({
            "thread_id": "t3_from_json",
            "title": "JSON Thread",
            "subreddit": "test",
            "author": "bot",
            "score": 0,
            "num_comments": 0,
            "created_utc": 0.0,
            "url": "",
            "relevance_rank": 1,
            "sentiment_signal": null
        });
        let ts: ThreadSummary = serde_json::from_value(v).unwrap();
        assert_eq!(ts.thread_id, "t3_from_json");
        assert!(ts.sentiment_signal.is_none());
    }

    #[test]
    fn thread_summary_with_sentiment_json() {
        let v = json!({
            "thread_id": "t3_sent",
            "title": "Sentiment",
            "subreddit": "test",
            "author": "user",
            "score": 100,
            "num_comments": 50,
            "created_utc": 1700000000.0,
            "url": "https://reddit.com",
            "relevance_rank": 1,
            "sentiment_signal": "Positive"
        });
        let ts: ThreadSummary = serde_json::from_value(v).unwrap();
        assert_eq!(ts.sentiment_signal, Some(SentimentSignal::Positive));
    }

    #[test]
    fn research_query_from_json() {
        let v = json!({
            "query": "from json",
            "subreddits": ["a", "b"],
            "time_window": "PastWeek",
            "min_score": 10,
            "min_comments": 5,
            "max_threads": 50
        });
        let q: ResearchQuery = serde_json::from_value(v).unwrap();
        assert_eq!(q.query, "from json");
        assert_eq!(q.subreddits.len(), 2);
        assert_eq!(q.time_window, TimeWindow::PastWeek);
        assert_eq!(q.min_score, Some(10));
    }

    #[test]
    fn evidence_request_from_json() {
        let v = json!({
            "thread_ids": ["t3_a"],
            "max_comments_per_thread": 100,
            "min_score": -5,
            "include_controversial": true,
            "max_depth": 8
        });
        let r: EvidenceRequest = serde_json::from_value(v).unwrap();
        assert_eq!(r.max_comments_per_thread, 100);
        assert!(r.include_controversial);
        assert_eq!(r.max_depth, 8);
    }

    #[test]
    fn truncate_preserves_short_string() {
        let b = ResearchBounds {
            max_excerpt_length: 100,
            ..ResearchBounds::default()
        };
        let input = "short";
        assert_eq!(b.truncate_excerpt(input), "short");
    }

    #[test]
    fn truncate_long_ascii() {
        let b = ResearchBounds {
            max_excerpt_length: 10,
            ..ResearchBounds::default()
        };
        let input = "abcdefghijklmnop";
        let result = b.truncate_excerpt(input);
        assert_eq!(result, "abcdefghij...");
        assert!(result.starts_with("abcdefghij"));
        assert!(result.ends_with("..."));
    }

    #[test]
    fn sentiment_signal_all_variants_serialize() {
        for s in &[
            SentimentSignal::Positive,
            SentimentSignal::Negative,
            SentimentSignal::Mixed,
            SentimentSignal::Neutral,
        ] {
            let v = serde_json::to_value(s).unwrap();
            let s2: SentimentSignal = serde_json::from_value(v).unwrap();
            assert_eq!(*s, s2);
        }
    }

    #[test]
    fn time_window_all_variants_filter() {
        let variants = vec![
            (TimeWindow::PastDay, "day"),
            (TimeWindow::PastWeek, "week"),
            (TimeWindow::PastMonth, "month"),
            (TimeWindow::PastYear, "year"),
            (TimeWindow::All, "all"),
            (
                TimeWindow::Custom {
                    after_utc: 0.0,
                    before_utc: 1.0,
                },
                "all",
            ),
        ];
        for (tw, expected) in variants {
            assert_eq!(tw.as_filter(), expected);
        }
    }

    #[test]
    fn research_bounds_validate_query_with_subreddits() {
        let b = ResearchBounds::default();
        let q = ResearchQuery::new("test")
            .add_subreddit("rust")
            .add_subreddit("programming");
        assert!(b.validate_query(&q).is_ok());
    }

    #[test]
    fn evidence_collection_many_excerpts() {
        let excerpts: Vec<EvidenceExcerpt> = (0_u32..100)
            .map(|i| EvidenceExcerpt {
                comment_id: format!("t1_{i}"),
                thread_id: "t3_batch".into(),
                author: format!("u{i}"),
                body_excerpt: format!("Comment {i}"),
                score: i64::from(i),
                depth: i % 5,
                parent_id: None,
                permalink: String::new(),
                created_utc: 0.0,
            })
            .collect();
        let c = EvidenceCollection {
            thread_id: "t3_batch".into(),
            excerpts,
            total_available: 500,
            collected: 100,
            truncated: true,
        };
        assert_eq!(c.len(), 100);
        assert!(c.truncated);
    }

    #[test]
    fn research_results_multiple_collections() {
        let collections: Vec<EvidenceCollection> = (0..5)
            .map(|i| EvidenceCollection {
                thread_id: format!("t3_{i}"),
                excerpts: vec![],
                total_available: 0,
                collected: 0,
                truncated: false,
            })
            .collect();
        let r = ResearchResults {
            collections,
            total_excerpts: 0,
            provenance: vec![],
        };
        assert_eq!(r.len(), 5);
    }

    #[test]
    fn evidence_request_validate_many_unique_ids() {
        let ids: Vec<String> = (0..20).map(|i| format!("t3_{i}")).collect();
        let r = EvidenceRequest::new(ids);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn research_query_constants() {
        assert_eq!(ResearchQuery::MAX_THREADS_LIMIT, 100);
        assert_eq!(ResearchQuery::DEFAULT_MAX_THREADS, 25);
    }

    #[test]
    fn evidence_request_constants() {
        assert_eq!(EvidenceRequest::MAX_COMMENTS_LIMIT, 200);
        assert_eq!(EvidenceRequest::DEFAULT_MAX_COMMENTS, 50);
        assert_eq!(EvidenceRequest::DEFAULT_MAX_DEPTH, 5);
    }

    #[test]
    fn audit_event_empty_query_hash() {
        let e = ResearchAuditEvent::search(0.0, "", 0);
        assert!(e.query_hash.is_some());
        // Empty string still produces a hash
    }

    #[test]
    fn audit_event_timestamp_preserved() {
        let ts = 1_700_000_000.123;
        let e = ResearchAuditEvent::collect(ts, 0, 0);
        assert!((e.timestamp - ts).abs() < f64::EPSILON);
    }

    #[test]
    fn research_bounds_custom_limits() {
        let b = ResearchBounds {
            max_threads: 10,
            max_comments_per_thread: 20,
            max_excerpt_length: 500,
            max_total_excerpts: 100,
        };
        assert_eq!(b.max_threads, 10);
        assert_eq!(b.max_comments_per_thread, 20);
        assert_eq!(b.max_excerpt_length, 500);
        assert_eq!(b.max_total_excerpts, 100);
    }

    #[test]
    fn provenance_pointer_from_json() {
        let v = json!({
            "thread_id": "t3_j",
            "comment_id": "t1_j",
            "subreddit": "json",
            "permalink": "/r/json/test"
        });
        let p: ProvenancePointer = serde_json::from_value(v).unwrap();
        assert_eq!(p.thread_id, "t3_j");
        assert_eq!(p.subreddit, "json");
    }

    #[test]
    fn evidence_excerpt_deep_nesting() {
        let e = EvidenceExcerpt {
            comment_id: "t1_deep".into(),
            thread_id: "t3_deep".into(),
            author: "deep_user".into(),
            body_excerpt: "Deep comment".into(),
            score: 1,
            depth: 99,
            parent_id: Some("t1_above".into()),
            permalink: String::new(),
            created_utc: 0.0,
        };
        assert_eq!(e.depth, 99);
    }

    #[test]
    fn thread_search_results_many_threads() {
        let threads: Vec<ThreadSummary> = (0_u32..100)
            .map(|i| ThreadSummary {
                thread_id: format!("t3_{i}"),
                title: format!("T{i}"),
                subreddit: "s".into(),
                author: "a".into(),
                score: i64::from(i),
                num_comments: 0,
                created_utc: 0.0,
                url: String::new(),
                relevance_rank: i + 1,
                sentiment_signal: Some(SentimentSignal::from_score(i64::from(i))),
            })
            .collect();
        let r = ThreadSearchResults {
            threads,
            query_echo: "batch".into(),
            total_found: Some(100),
            time_window: TimeWindow::All,
        };
        assert_eq!(r.len(), 100);
    }

    #[test]
    fn research_query_validate_boundary_max_threads() {
        let mut q = ResearchQuery::new("test");
        q.max_threads = 100;
        assert!(q.validate().is_ok());
    }

    #[test]
    fn evidence_request_validate_boundary_max_comments() {
        let mut r = EvidenceRequest::new(vec!["t3_a".into()]);
        r.max_comments_per_thread = 200;
        assert!(r.validate().is_ok());
    }

    #[test]
    fn research_bounds_validate_evidence_boundary() {
        let b = ResearchBounds {
            max_total_excerpts: 200,
            ..ResearchBounds::default()
        };
        // 1 thread * 200 comments = 200 = exactly at limit
        let r = EvidenceRequest::new(vec!["t3_a".into()]).with_max_comments(200);
        assert!(b.validate_evidence_request(&r).is_ok());
    }

    #[test]
    fn research_bounds_validate_evidence_just_over() {
        let b = ResearchBounds {
            max_total_excerpts: 199,
            ..ResearchBounds::default()
        };
        let r = EvidenceRequest::new(vec!["t3_a".into()]).with_max_comments(200);
        assert!(b.validate_evidence_request(&r).is_err());
    }

    #[test]
    fn sentiment_from_score_boundary_values() {
        // Boundaries: -5, 0, 10
        assert_eq!(SentimentSignal::from_score(-6), SentimentSignal::Negative);
        assert_eq!(SentimentSignal::from_score(-5), SentimentSignal::Negative);
        assert_eq!(SentimentSignal::from_score(-4), SentimentSignal::Mixed);
        assert_eq!(SentimentSignal::from_score(-1), SentimentSignal::Mixed);
        assert_eq!(SentimentSignal::from_score(0), SentimentSignal::Neutral);
        assert_eq!(SentimentSignal::from_score(1), SentimentSignal::Neutral);
        assert_eq!(SentimentSignal::from_score(9), SentimentSignal::Neutral);
        assert_eq!(SentimentSignal::from_score(10), SentimentSignal::Positive);
        assert_eq!(SentimentSignal::from_score(11), SentimentSignal::Positive);
    }

    #[test]
    fn truncate_single_char_over() {
        let b = ResearchBounds {
            max_excerpt_length: 1,
            ..ResearchBounds::default()
        };
        let result = b.truncate_excerpt("ab");
        assert_eq!(result, "a...");
    }

    #[test]
    fn truncate_zero_length_bound() {
        let b = ResearchBounds {
            max_excerpt_length: 0,
            ..ResearchBounds::default()
        };
        let result = b.truncate_excerpt("anything");
        assert_eq!(result, "...");
    }

    #[test]
    fn research_action_debug() {
        let dbg = format!("{:?}", ResearchAction::Search);
        assert!(dbg.contains("Search"));
        let dbg = format!("{:?}", ResearchAction::Collect);
        assert!(dbg.contains("Collect"));
    }

    #[test]
    fn research_action_clone() {
        let a = ResearchAction::Search;
        let a2 = a;
        assert_eq!(a, a2);
    }
}
