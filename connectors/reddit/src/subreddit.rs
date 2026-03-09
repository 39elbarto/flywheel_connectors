//! `Reddit` subreddit browsing, search, and metadata types.
//!
//! All content returned from these types is tainted external input
//! and must be treated as untrusted.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

// ── Subreddit metadata ──────────────────────────────────────────────────

/// Metadata about a `Reddit` subreddit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubredditInfo {
    /// Display name (e.g. "rust").
    pub name: String,
    /// Human-readable title.
    pub title: String,
    /// Optional long description.
    pub description: Option<String>,
    /// Subscriber count, if known.
    pub subscribers: Option<u64>,
    /// Currently active users, if known.
    pub active_users: Option<u64>,
    /// Whether the subreddit is marked NSFW.
    pub nsfw: bool,
    /// Whether the subreddit is quarantined.
    pub quarantined: bool,
    /// `Reddit` over-18 flag (often mirrors `nsfw`).
    pub over18: bool,
    /// Subreddit rules.
    #[serde(default)]
    pub rules: Vec<SubredditRule>,
    /// UTC timestamp of subreddit creation.
    pub created_utc: Option<f64>,
}

impl SubredditInfo {
    /// Returns `true` if the subreddit is restricted (NSFW or quarantined).
    #[must_use]
    pub const fn is_restricted(&self) -> bool {
        self.nsfw || self.quarantined
    }
}

/// A single rule defined by a subreddit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubredditRule {
    /// Short title of the rule.
    pub title: String,
    /// Full description of the rule.
    pub description: String,
    /// Priority ordering (lower = higher priority).
    pub priority: u32,
    /// Optional violation reason text.
    pub violation_reason: Option<String>,
}

// ── Post sorting ────────────────────────────────────────────────────────

/// Sort order for listing posts in a subreddit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PostSort {
    /// Hot (default trending).
    Hot,
    /// Newest first.
    New,
    /// Top posts within a time window.
    Top {
        /// Time window filter.
        time_filter: TimeFilter,
    },
    /// Rising posts.
    Rising,
    /// Most controversial within a time window.
    Controversial {
        /// Time window filter.
        time_filter: TimeFilter,
    },
    /// Best (algorithmic).
    Best,
}

impl PostSort {
    /// Returns the `Reddit` API path segment for this sort.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::New => "new",
            Self::Top { .. } => "top",
            Self::Rising => "rising",
            Self::Controversial { .. } => "controversial",
            Self::Best => "best",
        }
    }
}

/// Time window filter for top/controversial sorts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimeFilter {
    /// Last hour.
    Hour,
    /// Last 24 hours.
    Day,
    /// Last week.
    Week,
    /// Last month.
    Month,
    /// Last year.
    Year,
    /// All time.
    All,
}

impl TimeFilter {
    /// Returns the `Reddit` API query parameter value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Year => "year",
            Self::All => "all",
        }
    }
}

// ── Post listings ───────────────────────────────────────────────────────

/// A paginated listing of posts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostListing {
    /// The posts in this page.
    pub posts: Vec<PostSummary>,
    /// Cursor for the next page.
    pub after: Option<String>,
    /// Cursor for the previous page.
    pub before: Option<String>,
    /// Total count hint from the API.
    pub count: u32,
}

/// Summary of a single `Reddit` post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostSummary {
    /// Fullname identifier (e.g. "`t3_abc123`").
    pub id: String,
    /// Post title.
    pub title: String,
    /// Author username.
    pub author: String,
    /// Subreddit name (without "r/" prefix).
    pub subreddit: String,
    /// Net score (upvotes minus downvotes).
    pub score: i64,
    /// Number of comments.
    pub num_comments: u64,
    /// UTC creation timestamp.
    pub created_utc: f64,
    /// Permalink path (e.g. "/r/rust/comments/abc/title/").
    pub permalink: String,
    /// External URL for link posts.
    pub url: Option<String>,
    /// First 500 characters of self-text, if any.
    pub selftext_preview: Option<String>,
    /// Whether the post is NSFW.
    pub nsfw: bool,
    /// Whether the post is marked as a spoiler.
    pub spoiler: bool,
    /// Whether the post is stickied.
    pub stickied: bool,
    /// Detected post type.
    pub post_type: PostType,
}

/// Classification of a `Reddit` post.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PostType {
    /// Self/text post.
    Text,
    /// Link to external content.
    Link,
    /// Image post.
    Image,
    /// Video post.
    Video,
    /// Gallery of images.
    Gallery,
    /// Cross-posted from another subreddit.
    Crosspost,
    /// Unrecognised type.
    Unknown,
}

// ── Search ──────────────────────────────────────────────────────────────

/// Builder for constructing a `Reddit` search query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    /// The search query string.
    pub query: String,
    /// Restrict search to a specific subreddit.
    pub subreddit: Option<String>,
    /// Sort order for results.
    pub sort: SearchSort,
    /// Time window filter.
    pub time_filter: TimeFilter,
    /// Maximum results to return (capped at 100).
    pub limit: u32,
    /// Pagination cursor.
    pub after: Option<String>,
}

impl SearchQuery {
    /// Create a new search query with defaults.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            subreddit: None,
            sort: SearchSort::Relevance,
            time_filter: TimeFilter::All,
            limit: 25,
            after: None,
        }
    }

    /// Restrict the search to a specific subreddit.
    #[must_use]
    pub fn in_subreddit(mut self, subreddit: impl Into<String>) -> Self {
        self.subreddit = Some(subreddit.into());
        self
    }

    /// Set the sort order.
    #[must_use]
    pub const fn with_sort(mut self, sort: SearchSort) -> Self {
        self.sort = sort;
        self
    }

    /// Set the time filter.
    #[must_use]
    pub const fn with_time_filter(mut self, time_filter: TimeFilter) -> Self {
        self.time_filter = time_filter;
        self
    }

    /// Set the result limit (clamped to 1..=100).
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.limit = if limit == 0 {
            1
        } else if limit > 100 {
            100
        } else {
            limit
        };
        self
    }

    /// Set the pagination cursor.
    #[must_use]
    pub fn with_after(mut self, after: impl Into<String>) -> Self {
        self.after = Some(after.into());
        self
    }

    /// Validate the search query. Returns an error message if invalid.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        let trimmed = self.query.trim();
        if trimmed.is_empty() {
            return Some("query must not be empty".to_string());
        }
        if trimmed.len() > 512 {
            return Some(format!(
                "query too long ({} chars, max 512)",
                trimmed.len()
            ));
        }
        if self.limit == 0 || self.limit > 100 {
            return Some(format!("limit must be 1..=100, got {}", self.limit));
        }
        None
    }
}

/// Sort order for search results.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SearchSort {
    /// Most relevant first.
    Relevance,
    /// Hot/trending.
    Hot,
    /// Highest score.
    Top,
    /// Newest first.
    New,
    /// Most comments.
    Comments,
}

impl SearchSort {
    /// Returns the `Reddit` API query parameter value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Relevance => "relevance",
            Self::Hot => "hot",
            Self::Top => "top",
            Self::New => "new",
            Self::Comments => "comments",
        }
    }
}

/// Search results from the `Reddit` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    /// Matching posts.
    pub posts: Vec<PostSummary>,
    /// Estimated total results (may be absent or approximate).
    pub total_results: Option<u32>,
    /// Pagination cursor for next page.
    pub after: Option<String>,
    /// Echo of the original query string.
    pub query_echo: String,
}

// ── Content filtering ───────────────────────────────────────────────────

/// Filter configuration for controlling which content is returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFilter {
    /// Whether to include NSFW content.
    pub allow_nsfw: bool,
    /// Whether to include quarantined content.
    pub allow_quarantined: bool,
    /// Maximum number of results to return.
    pub max_results: usize,
    /// Subreddit names to exclude from results.
    pub blocked_subreddits: HashSet<String>,
}

impl ContentFilter {
    /// Create a safe default filter (no NSFW, no quarantined, limit 100).
    #[must_use]
    pub fn new_safe() -> Self {
        Self {
            allow_nsfw: false,
            allow_quarantined: false,
            max_results: 100,
            blocked_subreddits: HashSet::new(),
        }
    }

    /// Filter a list of posts according to this filter's settings.
    #[must_use]
    pub fn filter_posts(&self, posts: Vec<PostSummary>) -> Vec<PostSummary> {
        posts
            .into_iter()
            .filter(|p| {
                if !self.allow_nsfw && p.nsfw {
                    return false;
                }
                !self.blocked_subreddits.contains(&p.subreddit)
            })
            .take(self.max_results)
            .collect()
    }

    /// Check whether a subreddit passes this filter.
    #[must_use]
    pub fn allows_subreddit(&self, info: &SubredditInfo) -> bool {
        if !self.allow_nsfw && info.nsfw {
            return false;
        }
        if !self.allow_quarantined && info.quarantined {
            return false;
        }
        !self.blocked_subreddits.contains(&info.name)
    }
}

// ── Helper: truncate selftext ───────────────────────────────────────────

/// Truncate text to at most `max_chars` characters. If truncated, appends "...".
#[must_use]
pub fn truncate_selftext(text: &str, max_chars: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars {
        text.to_string()
    } else {
        let truncated: String = chars[..max_chars].iter().collect();
        format!("{truncated}...")
    }
}

/// Create a selftext preview (first 500 characters).
#[must_use]
pub fn selftext_preview(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(truncate_selftext(trimmed, 500))
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── helpers ─────────────────────────────────────────────────────────

    fn sample_subreddit_info() -> SubredditInfo {
        SubredditInfo {
            name: "rust".into(),
            title: "The Rust Programming Language".into(),
            description: Some("A place for all things Rust".into()),
            subscribers: Some(300_000),
            active_users: Some(1_200),
            nsfw: false,
            quarantined: false,
            over18: false,
            rules: vec![sample_rule()],
            created_utc: Some(1_350_000_000.0),
        }
    }

    fn sample_rule() -> SubredditRule {
        SubredditRule {
            title: "Be kind".into(),
            description: "Treat others with respect".into(),
            priority: 1,
            violation_reason: Some("Unkind behaviour".into()),
        }
    }

    fn sample_post() -> PostSummary {
        PostSummary {
            id: "t3_abc123".into(),
            title: "Hello Rust".into(),
            author: "ferris".into(),
            subreddit: "rust".into(),
            score: 42,
            num_comments: 7,
            created_utc: 1_700_000_000.0,
            permalink: "/r/rust/comments/abc123/hello_rust/".into(),
            url: Some("https://example.com".into()),
            selftext_preview: None,
            nsfw: false,
            spoiler: false,
            stickied: false,
            post_type: PostType::Link,
        }
    }

    fn nsfw_post() -> PostSummary {
        PostSummary {
            nsfw: true,
            subreddit: "nsfw_sub".into(),
            ..sample_post()
        }
    }

    // ── SubredditInfo ───────────────────────────────────────────────────

    #[test]
    fn subreddit_info_not_restricted() {
        let info = sample_subreddit_info();
        assert!(!info.is_restricted());
    }

    #[test]
    fn subreddit_info_restricted_nsfw() {
        let info = SubredditInfo {
            nsfw: true,
            ..sample_subreddit_info()
        };
        assert!(info.is_restricted());
    }

    #[test]
    fn subreddit_info_restricted_quarantined() {
        let info = SubredditInfo {
            quarantined: true,
            ..sample_subreddit_info()
        };
        assert!(info.is_restricted());
    }

    #[test]
    fn subreddit_info_restricted_both() {
        let info = SubredditInfo {
            nsfw: true,
            quarantined: true,
            ..sample_subreddit_info()
        };
        assert!(info.is_restricted());
    }

    #[test]
    fn subreddit_info_serde_roundtrip() {
        let info = sample_subreddit_info();
        let json = serde_json::to_value(&info).unwrap();
        let info2: SubredditInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info2.name, "rust");
        assert_eq!(info2.subscribers, Some(300_000));
    }

    #[test]
    fn subreddit_info_deserialize_minimal() {
        let info: SubredditInfo = serde_json::from_value(json!({
            "name": "test",
            "title": "Test Sub",
            "nsfw": false,
            "quarantined": false,
            "over18": false
        }))
        .unwrap();
        assert_eq!(info.name, "test");
        assert!(info.description.is_none());
        assert!(info.subscribers.is_none());
        assert!(info.rules.is_empty());
    }

    #[test]
    fn subreddit_info_clone() {
        let info = sample_subreddit_info();
        #[allow(clippy::redundant_clone)]
        let info2 = info.clone();
        assert_eq!(info2.name, "rust");
        assert_eq!(info2.rules.len(), 1);
    }

    #[test]
    fn subreddit_info_debug() {
        let info = sample_subreddit_info();
        let dbg = format!("{info:?}");
        assert!(dbg.contains("rust"));
        assert!(dbg.contains("300000"));
    }

    #[test]
    fn subreddit_info_no_subscribers() {
        let info = SubredditInfo {
            subscribers: None,
            active_users: None,
            ..sample_subreddit_info()
        };
        assert!(info.subscribers.is_none());
        assert!(info.active_users.is_none());
    }

    #[test]
    fn subreddit_info_over18_flag() {
        let info = SubredditInfo {
            over18: true,
            nsfw: false,
            ..sample_subreddit_info()
        };
        assert!(info.over18);
        // over18 alone does not trigger is_restricted
        assert!(!info.is_restricted());
    }

    #[test]
    fn subreddit_info_empty_rules() {
        let info = SubredditInfo {
            rules: vec![],
            ..sample_subreddit_info()
        };
        assert!(info.rules.is_empty());
    }

    #[test]
    fn subreddit_info_multiple_rules() {
        let info = SubredditInfo {
            rules: vec![
                SubredditRule {
                    title: "Rule 1".into(),
                    description: "First rule".into(),
                    priority: 0,
                    violation_reason: None,
                },
                SubredditRule {
                    title: "Rule 2".into(),
                    description: "Second rule".into(),
                    priority: 1,
                    violation_reason: Some("Violation".into()),
                },
            ],
            ..sample_subreddit_info()
        };
        assert_eq!(info.rules.len(), 2);
        assert!(info.rules[0].violation_reason.is_none());
        assert!(info.rules[1].violation_reason.is_some());
    }

    #[test]
    fn subreddit_info_created_utc() {
        let info = sample_subreddit_info();
        assert!(info.created_utc.unwrap() > 1_000_000_000.0);
    }

    // ── SubredditRule ───────────────────────────────────────────────────

    #[test]
    fn rule_serde_roundtrip() {
        let rule = sample_rule();
        let json = serde_json::to_value(&rule).unwrap();
        let rule2: SubredditRule = serde_json::from_value(json).unwrap();
        assert_eq!(rule2.title, "Be kind");
        assert_eq!(rule2.priority, 1);
    }

    #[test]
    fn rule_no_violation_reason() {
        let rule = SubredditRule {
            violation_reason: None,
            ..sample_rule()
        };
        assert!(rule.violation_reason.is_none());
    }

    #[test]
    fn rule_clone() {
        let rule = sample_rule();
        #[allow(clippy::redundant_clone)]
        let rule2 = rule.clone();
        assert_eq!(rule2.title, "Be kind");
    }

    #[test]
    fn rule_debug() {
        let rule = sample_rule();
        let dbg = format!("{rule:?}");
        assert!(dbg.contains("Be kind"));
    }

    #[test]
    fn rule_zero_priority() {
        let rule = SubredditRule {
            priority: 0,
            ..sample_rule()
        };
        assert_eq!(rule.priority, 0);
    }

    #[test]
    fn rule_high_priority() {
        let rule = SubredditRule {
            priority: 999,
            ..sample_rule()
        };
        assert_eq!(rule.priority, 999);
    }

    // ── PostSort ────────────────────────────────────────────────────────

    #[test]
    fn post_sort_hot_str() {
        assert_eq!(PostSort::Hot.as_str(), "hot");
    }

    #[test]
    fn post_sort_new_str() {
        assert_eq!(PostSort::New.as_str(), "new");
    }

    #[test]
    fn post_sort_top_str() {
        let sort = PostSort::Top {
            time_filter: TimeFilter::Week,
        };
        assert_eq!(sort.as_str(), "top");
    }

    #[test]
    fn post_sort_rising_str() {
        assert_eq!(PostSort::Rising.as_str(), "rising");
    }

    #[test]
    fn post_sort_controversial_str() {
        let sort = PostSort::Controversial {
            time_filter: TimeFilter::Month,
        };
        assert_eq!(sort.as_str(), "controversial");
    }

    #[test]
    fn post_sort_best_str() {
        assert_eq!(PostSort::Best.as_str(), "best");
    }

    #[test]
    fn post_sort_eq() {
        assert_eq!(PostSort::Hot, PostSort::Hot);
        assert_ne!(PostSort::Hot, PostSort::New);
    }

    #[test]
    fn post_sort_top_eq_same_filter() {
        let a = PostSort::Top {
            time_filter: TimeFilter::Day,
        };
        let b = PostSort::Top {
            time_filter: TimeFilter::Day,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn post_sort_top_ne_diff_filter() {
        let a = PostSort::Top {
            time_filter: TimeFilter::Day,
        };
        let b = PostSort::Top {
            time_filter: TimeFilter::Year,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn post_sort_serde_roundtrip() {
        let sort = PostSort::Top {
            time_filter: TimeFilter::All,
        };
        let json = serde_json::to_value(&sort).unwrap();
        let sort2: PostSort = serde_json::from_value(json).unwrap();
        assert_eq!(sort2.as_str(), "top");
    }

    #[test]
    fn post_sort_clone() {
        let sort = PostSort::Controversial {
            time_filter: TimeFilter::Hour,
        };
        #[allow(clippy::redundant_clone)]
        let sort2 = sort.clone();
        assert_eq!(sort2.as_str(), "controversial");
    }

    #[test]
    fn post_sort_debug() {
        let dbg = format!("{:?}", PostSort::Rising);
        assert!(dbg.contains("Rising"));
    }

    // ── TimeFilter ──────────────────────────────────────────────────────

    #[test]
    fn time_filter_hour() {
        assert_eq!(TimeFilter::Hour.as_str(), "hour");
    }

    #[test]
    fn time_filter_day() {
        assert_eq!(TimeFilter::Day.as_str(), "day");
    }

    #[test]
    fn time_filter_week() {
        assert_eq!(TimeFilter::Week.as_str(), "week");
    }

    #[test]
    fn time_filter_month() {
        assert_eq!(TimeFilter::Month.as_str(), "month");
    }

    #[test]
    fn time_filter_year() {
        assert_eq!(TimeFilter::Year.as_str(), "year");
    }

    #[test]
    fn time_filter_all() {
        assert_eq!(TimeFilter::All.as_str(), "all");
    }

    #[test]
    fn time_filter_eq() {
        assert_eq!(TimeFilter::Hour, TimeFilter::Hour);
        assert_ne!(TimeFilter::Hour, TimeFilter::Day);
    }

    #[test]
    fn time_filter_copy() {
        let t = TimeFilter::Week;
        let t2 = t;
        assert_eq!(t, t2);
    }

    #[test]
    fn time_filter_serde_roundtrip() {
        let t = TimeFilter::Month;
        let json = serde_json::to_value(t).unwrap();
        let t2: TimeFilter = serde_json::from_value(json).unwrap();
        assert_eq!(t2, TimeFilter::Month);
    }

    #[test]
    fn time_filter_debug() {
        let dbg = format!("{:?}", TimeFilter::Year);
        assert!(dbg.contains("Year"));
    }

    // ── PostListing ─────────────────────────────────────────────────────

    #[test]
    fn post_listing_empty() {
        let listing = PostListing {
            posts: vec![],
            after: None,
            before: None,
            count: 0,
        };
        assert!(listing.posts.is_empty());
        assert_eq!(listing.count, 0);
    }

    #[test]
    fn post_listing_with_posts() {
        let listing = PostListing {
            posts: vec![sample_post()],
            after: Some("t3_next".into()),
            before: None,
            count: 1,
        };
        assert_eq!(listing.posts.len(), 1);
        assert_eq!(listing.after.as_deref(), Some("t3_next"));
    }

    #[test]
    fn post_listing_serde_roundtrip() {
        let listing = PostListing {
            posts: vec![sample_post()],
            after: Some("cursor".into()),
            before: Some("prev".into()),
            count: 25,
        };
        let json = serde_json::to_value(&listing).unwrap();
        let listing2: PostListing = serde_json::from_value(json).unwrap();
        assert_eq!(listing2.count, 25);
        assert_eq!(listing2.posts.len(), 1);
    }

    #[test]
    fn post_listing_clone() {
        let listing = PostListing {
            posts: vec![sample_post()],
            after: None,
            before: None,
            count: 1,
        };
        #[allow(clippy::redundant_clone)]
        let listing2 = listing.clone();
        assert_eq!(listing2.posts.len(), 1);
    }

    #[test]
    fn post_listing_debug() {
        let listing = PostListing {
            posts: vec![],
            after: None,
            before: None,
            count: 0,
        };
        let dbg = format!("{listing:?}");
        assert!(dbg.contains("PostListing"));
    }

    // ── PostSummary ─────────────────────────────────────────────────────

    #[test]
    fn post_summary_serde_roundtrip() {
        let post = sample_post();
        let json = serde_json::to_value(&post).unwrap();
        let post2: PostSummary = serde_json::from_value(json).unwrap();
        assert_eq!(post2.id, "t3_abc123");
        assert_eq!(post2.score, 42);
    }

    #[test]
    fn post_summary_clone() {
        let post = sample_post();
        #[allow(clippy::redundant_clone)]
        let post2 = post.clone();
        assert_eq!(post2.title, "Hello Rust");
    }

    #[test]
    fn post_summary_debug() {
        let post = sample_post();
        let dbg = format!("{post:?}");
        assert!(dbg.contains("abc123"));
    }

    #[test]
    fn post_summary_negative_score() {
        let post = PostSummary {
            score: -100,
            ..sample_post()
        };
        assert_eq!(post.score, -100);
    }

    #[test]
    fn post_summary_nsfw() {
        let post = nsfw_post();
        assert!(post.nsfw);
    }

    #[test]
    fn post_summary_spoiler() {
        let post = PostSummary {
            spoiler: true,
            ..sample_post()
        };
        assert!(post.spoiler);
    }

    #[test]
    fn post_summary_stickied() {
        let post = PostSummary {
            stickied: true,
            ..sample_post()
        };
        assert!(post.stickied);
    }

    #[test]
    fn post_summary_text_type() {
        let post = PostSummary {
            post_type: PostType::Text,
            selftext_preview: Some("Hello world".into()),
            url: None,
            ..sample_post()
        };
        assert_eq!(post.post_type, PostType::Text);
        assert!(post.selftext_preview.is_some());
    }

    #[test]
    fn post_summary_image_type() {
        let post = PostSummary {
            post_type: PostType::Image,
            url: Some("https://i.redd.it/image.png".into()),
            ..sample_post()
        };
        assert_eq!(post.post_type, PostType::Image);
    }

    #[test]
    fn post_summary_video_type() {
        let post = PostSummary {
            post_type: PostType::Video,
            ..sample_post()
        };
        assert_eq!(post.post_type, PostType::Video);
    }

    #[test]
    fn post_summary_gallery_type() {
        let post = PostSummary {
            post_type: PostType::Gallery,
            ..sample_post()
        };
        assert_eq!(post.post_type, PostType::Gallery);
    }

    #[test]
    fn post_summary_crosspost_type() {
        let post = PostSummary {
            post_type: PostType::Crosspost,
            ..sample_post()
        };
        assert_eq!(post.post_type, PostType::Crosspost);
    }

    #[test]
    fn post_summary_unknown_type() {
        let post = PostSummary {
            post_type: PostType::Unknown,
            ..sample_post()
        };
        assert_eq!(post.post_type, PostType::Unknown);
    }

    #[test]
    fn post_summary_no_url() {
        let post = PostSummary {
            url: None,
            ..sample_post()
        };
        assert!(post.url.is_none());
    }

    #[test]
    fn post_summary_no_selftext() {
        let post = PostSummary {
            selftext_preview: None,
            ..sample_post()
        };
        assert!(post.selftext_preview.is_none());
    }

    #[test]
    fn post_summary_zero_comments() {
        let post = PostSummary {
            num_comments: 0,
            ..sample_post()
        };
        assert_eq!(post.num_comments, 0);
    }

    // ── PostType ────────────────────────────────────────────────────────

    #[test]
    fn post_type_eq() {
        assert_eq!(PostType::Text, PostType::Text);
        assert_ne!(PostType::Text, PostType::Link);
    }

    #[test]
    fn post_type_serde_roundtrip() {
        let pt = PostType::Gallery;
        let json = serde_json::to_value(&pt).unwrap();
        let pt2: PostType = serde_json::from_value(json).unwrap();
        assert_eq!(pt2, PostType::Gallery);
    }

    #[test]
    fn post_type_debug() {
        let dbg = format!("{:?}", PostType::Crosspost);
        assert!(dbg.contains("Crosspost"));
    }

    #[test]
    fn post_type_clone() {
        let pt = PostType::Video;
        #[allow(clippy::redundant_clone)]
        let pt2 = pt.clone();
        assert_eq!(pt2, PostType::Video);
    }

    // ── SearchQuery ─────────────────────────────────────────────────────

    #[test]
    fn search_query_new_defaults() {
        let sq = SearchQuery::new("rust async");
        assert_eq!(sq.query, "rust async");
        assert!(sq.subreddit.is_none());
        assert_eq!(sq.sort, SearchSort::Relevance);
        assert_eq!(sq.time_filter, TimeFilter::All);
        assert_eq!(sq.limit, 25);
        assert!(sq.after.is_none());
    }

    #[test]
    fn search_query_builder_chain() {
        let sq = SearchQuery::new("tokio")
            .in_subreddit("rust")
            .with_sort(SearchSort::Top)
            .with_time_filter(TimeFilter::Month)
            .with_limit(50)
            .with_after("t3_cursor");
        assert_eq!(sq.query, "tokio");
        assert_eq!(sq.subreddit.as_deref(), Some("rust"));
        assert_eq!(sq.sort, SearchSort::Top);
        assert_eq!(sq.time_filter, TimeFilter::Month);
        assert_eq!(sq.limit, 50);
        assert_eq!(sq.after.as_deref(), Some("t3_cursor"));
    }

    #[test]
    fn search_query_limit_clamped_zero() {
        let sq = SearchQuery::new("test").with_limit(0);
        assert_eq!(sq.limit, 1);
    }

    #[test]
    fn search_query_limit_clamped_over_100() {
        let sq = SearchQuery::new("test").with_limit(200);
        assert_eq!(sq.limit, 100);
    }

    #[test]
    fn search_query_limit_exact_100() {
        let sq = SearchQuery::new("test").with_limit(100);
        assert_eq!(sq.limit, 100);
    }

    #[test]
    fn search_query_limit_exact_1() {
        let sq = SearchQuery::new("test").with_limit(1);
        assert_eq!(sq.limit, 1);
    }

    #[test]
    fn search_query_validate_ok() {
        let sq = SearchQuery::new("hello");
        assert!(sq.validate().is_none());
    }

    #[test]
    fn search_query_validate_empty() {
        let sq = SearchQuery::new("");
        assert!(sq.validate().is_some());
        assert!(sq.validate().unwrap().contains("empty"));
    }

    #[test]
    fn search_query_validate_whitespace_only() {
        let sq = SearchQuery::new("   ");
        assert!(sq.validate().is_some());
    }

    #[test]
    fn search_query_validate_too_long() {
        let long = "a".repeat(513);
        let sq = SearchQuery::new(long);
        let err = sq.validate().unwrap();
        assert!(err.contains("too long"));
        assert!(err.contains("513"));
    }

    #[test]
    fn search_query_validate_max_length_ok() {
        let exact = "a".repeat(512);
        let sq = SearchQuery::new(exact);
        assert!(sq.validate().is_none());
    }

    #[test]
    fn search_query_serde_roundtrip() {
        let sq = SearchQuery::new("test").in_subreddit("rust");
        let json = serde_json::to_value(&sq).unwrap();
        let sq2: SearchQuery = serde_json::from_value(json).unwrap();
        assert_eq!(sq2.query, "test");
        assert_eq!(sq2.subreddit.as_deref(), Some("rust"));
    }

    #[test]
    fn search_query_clone() {
        let sq = SearchQuery::new("clone test");
        #[allow(clippy::redundant_clone)]
        let sq2 = sq.clone();
        assert_eq!(sq2.query, "clone test");
    }

    #[test]
    fn search_query_debug() {
        let sq = SearchQuery::new("debug test");
        let dbg = format!("{sq:?}");
        assert!(dbg.contains("debug test"));
    }

    #[test]
    fn search_query_from_string() {
        let query = String::from("owned string");
        let sq = SearchQuery::new(query);
        assert_eq!(sq.query, "owned string");
    }

    // ── SearchSort ──────────────────────────────────────────────────────

    #[test]
    fn search_sort_relevance() {
        assert_eq!(SearchSort::Relevance.as_str(), "relevance");
    }

    #[test]
    fn search_sort_hot() {
        assert_eq!(SearchSort::Hot.as_str(), "hot");
    }

    #[test]
    fn search_sort_top() {
        assert_eq!(SearchSort::Top.as_str(), "top");
    }

    #[test]
    fn search_sort_new() {
        assert_eq!(SearchSort::New.as_str(), "new");
    }

    #[test]
    fn search_sort_comments() {
        assert_eq!(SearchSort::Comments.as_str(), "comments");
    }

    #[test]
    fn search_sort_eq() {
        assert_eq!(SearchSort::Hot, SearchSort::Hot);
        assert_ne!(SearchSort::Hot, SearchSort::New);
    }

    #[test]
    fn search_sort_copy() {
        let s = SearchSort::Top;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn search_sort_serde_roundtrip() {
        let s = SearchSort::Comments;
        let json = serde_json::to_value(s).unwrap();
        let s2: SearchSort = serde_json::from_value(json).unwrap();
        assert_eq!(s2, SearchSort::Comments);
    }

    #[test]
    fn search_sort_debug() {
        let dbg = format!("{:?}", SearchSort::Relevance);
        assert!(dbg.contains("Relevance"));
    }

    // ── SearchResults ───────────────────────────────────────────────────

    #[test]
    fn search_results_empty() {
        let sr = SearchResults {
            posts: vec![],
            total_results: Some(0),
            after: None,
            query_echo: "nothing".into(),
        };
        assert!(sr.posts.is_empty());
        assert_eq!(sr.total_results, Some(0));
    }

    #[test]
    fn search_results_with_posts() {
        let sr = SearchResults {
            posts: vec![sample_post()],
            total_results: Some(1),
            after: Some("next".into()),
            query_echo: "rust".into(),
        };
        assert_eq!(sr.posts.len(), 1);
        assert_eq!(sr.query_echo, "rust");
    }

    #[test]
    fn search_results_serde_roundtrip() {
        let sr = SearchResults {
            posts: vec![],
            total_results: None,
            after: None,
            query_echo: "serde".into(),
        };
        let json = serde_json::to_value(&sr).unwrap();
        let sr2: SearchResults = serde_json::from_value(json).unwrap();
        assert_eq!(sr2.query_echo, "serde");
        assert!(sr2.total_results.is_none());
    }

    #[test]
    fn search_results_clone() {
        let sr = SearchResults {
            posts: vec![sample_post()],
            total_results: Some(100),
            after: None,
            query_echo: "clone".into(),
        };
        #[allow(clippy::redundant_clone)]
        let sr2 = sr.clone();
        assert_eq!(sr2.query_echo, "clone");
    }

    #[test]
    fn search_results_debug() {
        let sr = SearchResults {
            posts: vec![],
            total_results: None,
            after: None,
            query_echo: "dbg".into(),
        };
        let dbg = format!("{sr:?}");
        assert!(dbg.contains("dbg"));
    }

    // ── ContentFilter ───────────────────────────────────────────────────

    #[test]
    fn content_filter_new_safe_defaults() {
        let cf = ContentFilter::new_safe();
        assert!(!cf.allow_nsfw);
        assert!(!cf.allow_quarantined);
        assert_eq!(cf.max_results, 100);
        assert!(cf.blocked_subreddits.is_empty());
    }

    #[test]
    fn content_filter_blocks_nsfw() {
        let cf = ContentFilter::new_safe();
        let posts = vec![sample_post(), nsfw_post()];
        let filtered = cf.filter_posts(posts);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].nsfw);
    }

    #[test]
    fn content_filter_allows_nsfw_when_enabled() {
        let cf = ContentFilter {
            allow_nsfw: true,
            ..ContentFilter::new_safe()
        };
        let posts = vec![sample_post(), nsfw_post()];
        let filtered = cf.filter_posts(posts);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn content_filter_blocks_subreddit() {
        let mut cf = ContentFilter::new_safe();
        cf.blocked_subreddits.insert("rust".into());
        let posts = vec![sample_post()];
        let filtered = cf.filter_posts(posts);
        assert!(filtered.is_empty());
    }

    #[test]
    fn content_filter_max_results() {
        let cf = ContentFilter {
            max_results: 2,
            ..ContentFilter::new_safe()
        };
        let posts = vec![sample_post(), sample_post(), sample_post()];
        let filtered = cf.filter_posts(posts);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn content_filter_allows_safe_subreddit() {
        let cf = ContentFilter::new_safe();
        let info = sample_subreddit_info();
        assert!(cf.allows_subreddit(&info));
    }

    #[test]
    fn content_filter_blocks_nsfw_subreddit() {
        let cf = ContentFilter::new_safe();
        let info = SubredditInfo {
            nsfw: true,
            ..sample_subreddit_info()
        };
        assert!(!cf.allows_subreddit(&info));
    }

    #[test]
    fn content_filter_blocks_quarantined_subreddit() {
        let cf = ContentFilter::new_safe();
        let info = SubredditInfo {
            quarantined: true,
            ..sample_subreddit_info()
        };
        assert!(!cf.allows_subreddit(&info));
    }

    #[test]
    fn content_filter_allows_quarantined_when_enabled() {
        let cf = ContentFilter {
            allow_quarantined: true,
            ..ContentFilter::new_safe()
        };
        let info = SubredditInfo {
            quarantined: true,
            ..sample_subreddit_info()
        };
        assert!(cf.allows_subreddit(&info));
    }

    #[test]
    fn content_filter_blocks_blocked_subreddit_name() {
        let mut cf = ContentFilter::new_safe();
        cf.blocked_subreddits.insert("rust".into());
        let info = sample_subreddit_info();
        assert!(!cf.allows_subreddit(&info));
    }

    #[test]
    fn content_filter_serde_roundtrip() {
        let mut cf = ContentFilter::new_safe();
        cf.blocked_subreddits.insert("blocked".into());
        let json = serde_json::to_value(&cf).unwrap();
        let cf2: ContentFilter = serde_json::from_value(json).unwrap();
        assert!(!cf2.allow_nsfw);
        assert!(cf2.blocked_subreddits.contains("blocked"));
    }

    #[test]
    fn content_filter_clone() {
        let cf = ContentFilter::new_safe();
        #[allow(clippy::redundant_clone)]
        let cf2 = cf.clone();
        assert_eq!(cf2.max_results, 100);
    }

    #[test]
    fn content_filter_debug() {
        let cf = ContentFilter::new_safe();
        let dbg = format!("{cf:?}");
        assert!(dbg.contains("ContentFilter"));
    }

    #[test]
    fn content_filter_empty_posts() {
        let cf = ContentFilter::new_safe();
        let filtered = cf.filter_posts(vec![]);
        assert!(filtered.is_empty());
    }

    #[test]
    fn content_filter_all_blocked() {
        let cf = ContentFilter::new_safe();
        let posts = vec![nsfw_post(), nsfw_post()];
        let filtered = cf.filter_posts(posts);
        assert!(filtered.is_empty());
    }

    #[test]
    fn content_filter_max_results_zero() {
        let cf = ContentFilter {
            max_results: 0,
            ..ContentFilter::new_safe()
        };
        let posts = vec![sample_post()];
        let filtered = cf.filter_posts(posts);
        assert!(filtered.is_empty());
    }

    #[test]
    fn content_filter_nsfw_and_blocked_combined() {
        let mut cf = ContentFilter::new_safe();
        cf.blocked_subreddits.insert("other".into());
        let posts = vec![
            sample_post(), // subreddit "rust", not nsfw — passes
            nsfw_post(),   // nsfw — blocked
            PostSummary {
                subreddit: "other".into(),
                ..sample_post()
            }, // blocked sub — blocked
        ];
        let filtered = cf.filter_posts(posts);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].subreddit, "rust");
    }

    // ── truncate_selftext / selftext_preview ────────────────────────────

    #[test]
    fn truncate_short_text() {
        assert_eq!(truncate_selftext("hello", 500), "hello");
    }

    #[test]
    fn truncate_exact_length() {
        let text = "a".repeat(500);
        assert_eq!(truncate_selftext(&text, 500), text);
    }

    #[test]
    fn truncate_long_text() {
        let text = "a".repeat(501);
        let result = truncate_selftext(&text, 500);
        assert_eq!(result.len(), 503); // 500 + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_empty() {
        assert_eq!(truncate_selftext("", 500), "");
    }

    #[test]
    fn truncate_unicode() {
        // Each emoji is multiple bytes but one char
        let text = "\u{1F600}".repeat(501); // 501 emoji chars
        let result = truncate_selftext(&text, 500);
        assert!(result.ends_with("..."));
        // Should be 500 emoji + "..."
        assert_eq!(result.chars().count(), 503); // 500 + 3 dots
    }

    #[test]
    fn selftext_preview_normal() {
        let result = selftext_preview("Hello, world!");
        assert_eq!(result, Some("Hello, world!".into()));
    }

    #[test]
    fn selftext_preview_empty() {
        assert!(selftext_preview("").is_none());
    }

    #[test]
    fn selftext_preview_whitespace() {
        assert!(selftext_preview("   ").is_none());
    }

    #[test]
    fn selftext_preview_long() {
        let text = "x".repeat(600);
        let result = selftext_preview(&text).unwrap();
        assert!(result.ends_with("..."));
        assert_eq!(result.chars().count(), 503);
    }

    #[test]
    fn selftext_preview_trims() {
        let result = selftext_preview("  trimmed  ").unwrap();
        assert_eq!(result, "trimmed");
    }

    // ── Additional edge-case coverage ───────────────────────────────────

    #[test]
    fn post_listing_both_cursors() {
        let listing = PostListing {
            posts: vec![],
            after: Some("after_cursor".into()),
            before: Some("before_cursor".into()),
            count: 50,
        };
        assert!(listing.after.is_some());
        assert!(listing.before.is_some());
    }

    #[test]
    fn subreddit_info_serialize_snake_case() {
        let info = sample_subreddit_info();
        let json = serde_json::to_value(&info).unwrap();
        // Reddit API uses snake_case — verify keys
        assert!(json.get("name").is_some());
        assert!(json.get("active_users").is_some());
        assert!(json.get("created_utc").is_some());
        // Should NOT have camelCase keys
        assert!(json.get("activeUsers").is_none());
        assert!(json.get("createdUtc").is_none());
    }

    #[test]
    fn post_summary_serialize_snake_case() {
        let post = sample_post();
        let json = serde_json::to_value(&post).unwrap();
        assert!(json.get("num_comments").is_some());
        assert!(json.get("created_utc").is_some());
        assert!(json.get("selftext_preview").is_some());
        assert!(json.get("post_type").is_some());
        // No camelCase
        assert!(json.get("numComments").is_none());
        assert!(json.get("postType").is_none());
    }

    #[test]
    fn search_query_validate_single_char() {
        let sq = SearchQuery::new("x");
        assert!(sq.validate().is_none());
    }

    #[test]
    fn search_query_with_after_string() {
        let sq = SearchQuery::new("test").with_after(String::from("t3_abc"));
        assert_eq!(sq.after.as_deref(), Some("t3_abc"));
    }

    #[test]
    fn content_filter_multiple_blocked() {
        let mut cf = ContentFilter::new_safe();
        cf.blocked_subreddits.insert("sub_a".into());
        cf.blocked_subreddits.insert("sub_b".into());
        let posts = vec![
            PostSummary {
                subreddit: "sub_a".into(),
                ..sample_post()
            },
            PostSummary {
                subreddit: "sub_b".into(),
                ..sample_post()
            },
            PostSummary {
                subreddit: "sub_c".into(),
                ..sample_post()
            },
        ];
        let filtered = cf.filter_posts(posts);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].subreddit, "sub_c");
    }

    #[test]
    fn post_sort_all_variants_distinct_str() {
        let strs: Vec<&str> = vec![
            PostSort::Hot.as_str(),
            PostSort::New.as_str(),
            PostSort::Top {
                time_filter: TimeFilter::All,
            }
            .as_str(),
            PostSort::Rising.as_str(),
            PostSort::Controversial {
                time_filter: TimeFilter::All,
            }
            .as_str(),
            PostSort::Best.as_str(),
        ];
        // All should be unique
        let set: HashSet<&str> = strs.iter().copied().collect();
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn search_sort_all_variants_distinct_str() {
        let strs: Vec<&str> = vec![
            SearchSort::Relevance.as_str(),
            SearchSort::Hot.as_str(),
            SearchSort::Top.as_str(),
            SearchSort::New.as_str(),
            SearchSort::Comments.as_str(),
        ];
        let set: HashSet<&str> = strs.iter().copied().collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn time_filter_all_variants_distinct_str() {
        let strs: Vec<&str> = vec![
            TimeFilter::Hour.as_str(),
            TimeFilter::Day.as_str(),
            TimeFilter::Week.as_str(),
            TimeFilter::Month.as_str(),
            TimeFilter::Year.as_str(),
            TimeFilter::All.as_str(),
        ];
        let set: HashSet<&str> = strs.iter().copied().collect();
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn truncate_selftext_one_char() {
        assert_eq!(truncate_selftext("x", 1), "x");
    }

    #[test]
    fn truncate_selftext_two_chars_limit_one() {
        let result = truncate_selftext("ab", 1);
        assert_eq!(result, "a...");
    }

    #[test]
    fn post_summary_large_score() {
        let post = PostSummary {
            score: i64::MAX,
            ..sample_post()
        };
        assert_eq!(post.score, i64::MAX);
    }

    #[test]
    fn post_summary_large_comments() {
        let post = PostSummary {
            num_comments: u64::MAX,
            ..sample_post()
        };
        assert_eq!(post.num_comments, u64::MAX);
    }

    #[test]
    fn subreddit_info_large_subscribers() {
        let info = SubredditInfo {
            subscribers: Some(u64::MAX),
            ..sample_subreddit_info()
        };
        assert_eq!(info.subscribers, Some(u64::MAX));
    }

    #[test]
    fn content_filter_allows_nsfw_subreddit_when_enabled() {
        let cf = ContentFilter {
            allow_nsfw: true,
            ..ContentFilter::new_safe()
        };
        let info = SubredditInfo {
            nsfw: true,
            ..sample_subreddit_info()
        };
        assert!(cf.allows_subreddit(&info));
    }

    #[test]
    fn search_query_limit_boundary_99() {
        let sq = SearchQuery::new("test").with_limit(99);
        assert_eq!(sq.limit, 99);
    }

    #[test]
    fn search_query_limit_boundary_101() {
        let sq = SearchQuery::new("test").with_limit(101);
        assert_eq!(sq.limit, 100);
    }
}
