//! `Reddit` post and comment reading with bounded traversal.
//!
//! Provides safe, read-only access to `Reddit` post content, comment threads,
//! and user history. All content returned is considered tainted. Comment tree
//! expansion is bounded by configurable depth and count limits to prevent
//! unbounded recursion.

use serde::{Deserialize, Serialize};

// ── Post Types ──────────────────────────────────────────────────────────

/// The type of a `Reddit` post.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostType {
    /// Self/text post.
    Text,
    /// Link post pointing to an external URL.
    Link,
    /// Image post.
    Image,
    /// Video post (hosted or external).
    Video,
    /// Gallery post with multiple images.
    Gallery,
    /// Poll post.
    Poll,
    /// Crosspost from another subreddit.
    Crosspost,
    /// Unknown or unrecognised post type.
    Unknown,
}

impl PostType {
    /// Returns a human-readable label for the post type.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Link => "link",
            Self::Image => "image",
            Self::Video => "video",
            Self::Gallery => "gallery",
            Self::Poll => "poll",
            Self::Crosspost => "crosspost",
            Self::Unknown => "unknown",
        }
    }
}

/// A `Reddit` post with full details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Post {
    /// Post fullname (e.g. `t3_abc123`).
    pub id: String,
    /// Post title.
    pub title: String,
    /// Author username.
    pub author: String,
    /// Subreddit name (without `r/` prefix).
    pub subreddit: String,
    /// Self-text body (only for text posts).
    pub selftext: Option<String>,
    /// URL for link/image/video posts.
    pub url: Option<String>,
    /// Net score (upvotes minus downvotes).
    pub score: i64,
    /// Ratio of upvotes to total votes.
    pub upvote_ratio: Option<f64>,
    /// Number of comments.
    pub num_comments: u32,
    /// UTC timestamp of creation.
    pub created_utc: f64,
    /// UTC timestamp of last edit, if edited.
    pub edited: Option<f64>,
    /// Permalink path (e.g. `/r/rust/comments/abc123/title/`).
    pub permalink: String,
    /// Link flair text, if any.
    pub link_flair_text: Option<String>,
    /// Whether the post is marked NSFW.
    pub nsfw: bool,
    /// Whether the post is marked as a spoiler.
    pub spoiler: bool,
    /// Whether the post is locked.
    pub locked: bool,
    /// Whether the post is archived.
    pub archived: bool,
    /// Detected post type.
    pub post_type: PostType,
}

// ── Comment Types ───────────────────────────────────────────────────────

/// A single `Reddit` comment with nested replies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    /// Comment fullname (e.g. `t1_xyz789`).
    pub id: String,
    /// Author username.
    pub author: String,
    /// Comment body (markdown).
    pub body: String,
    /// Net score.
    pub score: i64,
    /// UTC timestamp of creation.
    pub created_utc: f64,
    /// UTC timestamp of last edit, if edited.
    pub edited: Option<f64>,
    /// Nesting depth (0 = top-level).
    pub depth: u32,
    /// Parent fullname (`t3_*` for top-level, `t1_*` for reply).
    pub parent_id: Option<String>,
    /// Whether the author is the original poster.
    pub is_op: bool,
    /// Whether the comment is stickied by a moderator.
    pub stickied: bool,
    /// Nested child replies.
    #[serde(default)]
    pub replies: Vec<Self>,
    /// Count of additional unexpanded children (`"more"` stubs).
    pub more_count: Option<u32>,
}

/// A bounded comment tree for a post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentTree {
    /// The post this tree belongs to.
    pub post_id: String,
    /// Top-level comments (with nested replies).
    pub comments: Vec<Comment>,
    /// Total number of comments loaded in this tree.
    pub total_loaded: u32,
    /// Total comments available on the post (from post metadata).
    pub total_available: Option<u32>,
    /// Whether the configured max depth was reached.
    pub max_depth_reached: bool,
    /// Whether the tree was truncated due to limits.
    pub truncated: bool,
}

// ── Comment Fetch Configuration ─────────────────────────────────────────

/// Sort order for comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommentSort {
    /// `Reddit` "best" (confidence-weighted).
    Best,
    /// Most upvoted.
    Top,
    /// Most recent first.
    New,
    /// Most controversial.
    Controversial,
    /// Oldest first.
    Old,
    /// Q&A mode.
    Qa,
}

impl CommentSort {
    /// Returns the API query parameter value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Best => "confidence",
            Self::Top => "top",
            Self::New => "new",
            Self::Controversial => "controversial",
            Self::Old => "old",
            Self::Qa => "qa",
        }
    }
}

/// Configuration for fetching a comment tree with bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentFetchConfig {
    /// Maximum number of comments to load.
    pub max_comments: u32,
    /// Maximum nesting depth to traverse.
    pub max_depth: u32,
    /// Sort order.
    pub sort: CommentSort,
    /// Whether to expand "more comments" stubs.
    pub expand_more: bool,
}

impl Default for CommentFetchConfig {
    fn default() -> Self {
        Self {
            max_comments: 200,
            max_depth: 10,
            sort: CommentSort::Best,
            expand_more: false,
        }
    }
}

impl CommentFetchConfig {
    /// Create a new config with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of comments to load.
    #[must_use]
    pub const fn with_max_comments(mut self, n: u32) -> Self {
        self.max_comments = n;
        self
    }

    /// Set the maximum nesting depth.
    #[must_use]
    pub const fn with_max_depth(mut self, d: u32) -> Self {
        self.max_depth = d;
        self
    }

    /// Set the sort order.
    #[must_use]
    pub const fn with_sort(mut self, sort: CommentSort) -> Self {
        self.sort = sort;
        self
    }

    /// Set whether to expand "more comments" stubs.
    #[must_use]
    pub const fn with_expand_more(mut self, expand: bool) -> Self {
        self.expand_more = expand;
        self
    }

    /// Validate the configuration. Returns an error message if invalid.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a description if `max_comments` is 0 or exceeds
    /// 1000, or if `max_depth` exceeds 50.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_comments == 0 {
            return Err("max_comments must be at least 1".into());
        }
        if self.max_comments > 1000 {
            return Err(format!(
                "max_comments {} exceeds limit of 1000",
                self.max_comments
            ));
        }
        if self.max_depth > 50 {
            return Err(format!("max_depth {} exceeds limit of 50", self.max_depth));
        }
        Ok(())
    }
}

// ── User History Types ──────────────────────────────────────────────────

/// A summary of a `Reddit` post (lighter than full `Post`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostSummary {
    /// Post fullname.
    pub id: String,
    /// Post title.
    pub title: String,
    /// Subreddit name.
    pub subreddit: String,
    /// Net score.
    pub score: i64,
    /// Number of comments.
    pub num_comments: u32,
    /// UTC timestamp of creation.
    pub created_utc: f64,
}

/// A comment from a user's history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserComment {
    /// Comment fullname.
    pub id: String,
    /// Comment body (markdown).
    pub body: String,
    /// Subreddit the comment was posted in.
    pub subreddit: String,
    /// Title of the parent post, if available.
    pub post_title: Option<String>,
    /// Net score.
    pub score: i64,
    /// UTC timestamp of creation.
    pub created_utc: f64,
    /// Permalink to the comment.
    pub permalink: String,
}

/// Read-only view of a `Reddit` user's post and comment history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserHistory {
    /// The username.
    pub username: String,
    /// Recent posts by this user.
    pub posts: Vec<PostSummary>,
    /// Recent comments by this user.
    pub comments: Vec<UserComment>,
    /// Total karma, if available.
    pub total_karma: Option<i64>,
}

// ── Content Bounds ──────────────────────────────────────────────────────

/// Safety bounds for text content lengths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentBounds {
    /// Maximum length for post self-text.
    pub max_selftext_length: usize,
    /// Maximum length for a single comment body.
    pub max_comment_body_length: usize,
    /// Maximum number of items in user history.
    pub max_history_items: usize,
}

impl Default for ContentBounds {
    fn default() -> Self {
        Self {
            max_selftext_length: 40_000,
            max_comment_body_length: 10_000,
            max_history_items: 100,
        }
    }
}

impl ContentBounds {
    /// Truncate text to the given limit at a safe character boundary.
    ///
    /// If the text fits within `limit`, it is returned unchanged. Otherwise
    /// it is truncated to the last valid char boundary at or before `limit`
    /// and suffixed with `...`.
    #[must_use]
    pub fn truncate_text(text: &str, limit: usize) -> String {
        if text.len() <= limit {
            return text.to_owned();
        }
        // Find the last char boundary at or before `limit`.
        let mut end = limit;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        let mut result = text[..end].to_owned();
        result.push_str("...");
        result
    }
}

// ── Helper Functions ────────────────────────────────────────────────────

/// Count total comments in a tree, including nested replies.
#[must_use]
pub fn count_comments(comments: &[Comment]) -> u32 {
    let mut total: u32 = 0;
    for c in comments {
        total = total.saturating_add(1);
        total = total.saturating_add(count_comments(&c.replies));
    }
    total
}

/// Find the maximum depth in a comment tree.
#[must_use]
pub fn max_depth(comments: &[Comment]) -> u32 {
    comments
        .iter()
        .map(|c| {
            if c.replies.is_empty() {
                c.depth
            } else {
                max_depth(&c.replies)
            }
        })
        .max()
        .unwrap_or(0)
}

/// Flatten a comment tree into a depth-first ordered list.
#[must_use]
pub fn flatten_comments(comments: &[Comment]) -> Vec<&Comment> {
    let mut out = Vec::new();
    for c in comments {
        out.push(c);
        out.extend(flatten_comments(&c.replies));
    }
    out
}

/// Truncate a comment tree to respect depth and count bounds.
///
/// Returns the truncated tree and whether truncation occurred.
pub fn truncate_tree(comments: &[Comment], config: &CommentFetchConfig) -> (Vec<Comment>, bool) {
    let mut result = Vec::new();
    let mut remaining = config.max_comments;
    let mut truncated = false;

    truncate_recursive(
        comments,
        config.max_depth,
        &mut remaining,
        &mut truncated,
        &mut result,
    );

    (result, truncated)
}

fn truncate_recursive(
    comments: &[Comment],
    max_depth: u32,
    remaining: &mut u32,
    truncated: &mut bool,
    out: &mut Vec<Comment>,
) {
    for c in comments {
        if *remaining == 0 {
            *truncated = true;
            return;
        }

        let mut cloned = c.clone();

        if c.depth >= max_depth {
            // Don't include deeper replies.
            if !cloned.replies.is_empty() {
                cloned.more_count =
                    Some(cloned.more_count.unwrap_or(0) + count_comments(&cloned.replies));
                cloned.replies.clear();
                *truncated = true;
            }
        } else {
            // Recursively truncate children.
            let mut child_out = Vec::new();
            *remaining = remaining.saturating_sub(1);
            truncate_recursive(&c.replies, max_depth, remaining, truncated, &mut child_out);
            cloned.replies = child_out;
            out.push(cloned);
            continue;
        }

        *remaining = remaining.saturating_sub(1);
        out.push(cloned);
    }
}

/// Build a `CommentTree` from a list of comments with bounding.
#[must_use]
pub fn build_comment_tree(
    post_id: &str,
    comments: &[Comment],
    total_available: Option<u32>,
    config: &CommentFetchConfig,
) -> CommentTree {
    let (bounded, truncated) = truncate_tree(comments, config);
    let total_loaded = count_comments(&bounded);
    let depth_reached = max_depth(&bounded);

    CommentTree {
        post_id: post_id.to_owned(),
        comments: bounded,
        total_loaded,
        total_available,
        max_depth_reached: depth_reached >= config.max_depth,
        truncated,
    }
}

/// Apply `ContentBounds` to a `Post`, truncating self-text if needed.
pub fn apply_bounds_to_post(post: &mut Post, bounds: &ContentBounds) {
    if let Some(ref text) = post.selftext {
        if text.len() > bounds.max_selftext_length {
            post.selftext = Some(ContentBounds::truncate_text(
                text,
                bounds.max_selftext_length,
            ));
        }
    }
}

/// Apply `ContentBounds` to comments, truncating bodies.
pub fn apply_bounds_to_comments(comments: &mut [Comment], bounds: &ContentBounds) {
    for c in comments {
        if c.body.len() > bounds.max_comment_body_length {
            c.body = ContentBounds::truncate_text(&c.body, bounds.max_comment_body_length);
        }
        apply_bounds_to_comments(&mut c.replies, bounds);
    }
}

/// Apply `ContentBounds` to user history, truncating items and text.
pub fn apply_bounds_to_history(history: &mut UserHistory, bounds: &ContentBounds) {
    history.posts.truncate(bounds.max_history_items);
    history.comments.truncate(bounds.max_history_items);
    for uc in &mut history.comments {
        if uc.body.len() > bounds.max_comment_body_length {
            uc.body = ContentBounds::truncate_text(&uc.body, bounds.max_comment_body_length);
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Helpers ─────────────────────────────────────────────────────

    fn make_post(id: &str, post_type: PostType) -> Post {
        Post {
            id: id.into(),
            title: format!("Post {id}"),
            author: "testuser".into(),
            subreddit: "rust".into(),
            selftext: Some("Hello world".into()),
            url: None,
            score: 42,
            upvote_ratio: Some(0.95),
            num_comments: 5,
            created_utc: 1_700_000_000.0,
            edited: None,
            permalink: format!("/r/rust/comments/{id}/post/"),
            link_flair_text: None,
            nsfw: false,
            spoiler: false,
            locked: false,
            archived: false,
            post_type,
        }
    }

    fn make_comment(id: &str, depth: u32, replies: Vec<Comment>) -> Comment {
        Comment {
            id: id.into(),
            author: "commenter".into(),
            body: format!("Comment {id}"),
            score: 10,
            created_utc: 1_700_000_100.0,
            edited: None,
            depth,
            parent_id: None,
            is_op: false,
            stickied: false,
            replies,
            more_count: None,
        }
    }

    fn make_deep_chain(max_depth: u32) -> Comment {
        fn inner(current: u32, max: u32) -> Comment {
            let mut c = make_comment(&format!("d{current}"), current, vec![]);
            if current < max {
                c.replies.push(inner(current + 1, max));
            }
            c
        }
        inner(0, max_depth)
    }

    // ── PostType tests ──────────────────────────────────────────────

    #[test]
    fn post_type_label() {
        assert_eq!(PostType::Text.label(), "text");
        assert_eq!(PostType::Link.label(), "link");
        assert_eq!(PostType::Image.label(), "image");
        assert_eq!(PostType::Video.label(), "video");
        assert_eq!(PostType::Gallery.label(), "gallery");
        assert_eq!(PostType::Poll.label(), "poll");
        assert_eq!(PostType::Crosspost.label(), "crosspost");
        assert_eq!(PostType::Unknown.label(), "unknown");
    }

    #[test]
    fn post_type_serde_roundtrip() {
        for pt in [
            PostType::Text,
            PostType::Link,
            PostType::Image,
            PostType::Video,
            PostType::Gallery,
            PostType::Poll,
            PostType::Crosspost,
            PostType::Unknown,
        ] {
            let v = serde_json::to_value(pt).unwrap();
            let back: PostType = serde_json::from_value(v).unwrap();
            assert_eq!(pt, back);
        }
    }

    #[test]
    fn post_type_clone() {
        let pt = PostType::Gallery;
        let pt2 = pt;
        assert_eq!(pt, pt2);
    }

    #[test]
    fn post_type_debug() {
        let dbg = format!("{:?}", PostType::Poll);
        assert!(dbg.contains("Poll"));
    }

    #[test]
    fn post_type_eq() {
        assert_eq!(PostType::Text, PostType::Text);
        assert_ne!(PostType::Text, PostType::Link);
    }

    // ── Post tests ──────────────────────────────────────────────────

    #[test]
    fn post_serde_roundtrip() {
        let p = make_post("abc123", PostType::Text);
        let v = serde_json::to_value(&p).unwrap();
        let p2: Post = serde_json::from_value(v).unwrap();
        assert_eq!(p2.id, "abc123");
        assert_eq!(p2.title, "Post abc123");
        assert_eq!(p2.score, 42);
    }

    #[test]
    fn post_text_type() {
        let p = make_post("t1", PostType::Text);
        assert_eq!(p.post_type, PostType::Text);
        assert!(p.selftext.is_some());
    }

    #[test]
    fn post_link_type() {
        let mut p = make_post("t2", PostType::Link);
        p.selftext = None;
        p.url = Some("https://example.com".into());
        assert_eq!(p.post_type, PostType::Link);
        assert!(p.url.is_some());
        assert!(p.selftext.is_none());
    }

    #[test]
    fn post_image_type() {
        let mut p = make_post("t3", PostType::Image);
        p.url = Some("https://i.redd.it/abc.jpg".into());
        assert_eq!(p.post_type, PostType::Image);
    }

    #[test]
    fn post_video_type() {
        let p = make_post("t4", PostType::Video);
        assert_eq!(p.post_type, PostType::Video);
    }

    #[test]
    fn post_gallery_type() {
        let p = make_post("t5", PostType::Gallery);
        assert_eq!(p.post_type, PostType::Gallery);
    }

    #[test]
    fn post_poll_type() {
        let p = make_post("t6", PostType::Poll);
        assert_eq!(p.post_type, PostType::Poll);
    }

    #[test]
    fn post_crosspost_type() {
        let p = make_post("t7", PostType::Crosspost);
        assert_eq!(p.post_type, PostType::Crosspost);
    }

    #[test]
    fn post_unknown_type() {
        let p = make_post("t8", PostType::Unknown);
        assert_eq!(p.post_type, PostType::Unknown);
    }

    #[test]
    fn post_with_flair() {
        let mut p = make_post("flair1", PostType::Text);
        p.link_flair_text = Some("Discussion".into());
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["link_flair_text"], "Discussion");
    }

    #[test]
    fn post_nsfw() {
        let mut p = make_post("nsfw1", PostType::Text);
        p.nsfw = true;
        assert!(p.nsfw);
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["nsfw"], true);
    }

    #[test]
    fn post_spoiler() {
        let mut p = make_post("sp1", PostType::Text);
        p.spoiler = true;
        assert!(p.spoiler);
    }

    #[test]
    fn post_locked() {
        let mut p = make_post("lk1", PostType::Text);
        p.locked = true;
        assert!(p.locked);
    }

    #[test]
    fn post_archived() {
        let mut p = make_post("ar1", PostType::Text);
        p.archived = true;
        assert!(p.archived);
    }

    #[test]
    fn post_edited() {
        let mut p = make_post("ed1", PostType::Text);
        p.edited = Some(1_700_001_000.0);
        let v = serde_json::to_value(&p).unwrap();
        let p2: Post = serde_json::from_value(v).unwrap();
        assert_eq!(p2.edited, Some(1_700_001_000.0));
    }

    #[test]
    fn post_negative_score() {
        let mut p = make_post("neg", PostType::Text);
        p.score = -100;
        assert_eq!(p.score, -100);
    }

    #[test]
    fn post_zero_comments() {
        let mut p = make_post("zero", PostType::Text);
        p.num_comments = 0;
        assert_eq!(p.num_comments, 0);
    }

    #[test]
    fn post_clone() {
        let p = make_post("cl1", PostType::Text);
        let p2 = p.clone();
        assert_eq!(p.id, p2.id);
        assert_eq!(p.title, p2.title);
    }

    #[test]
    fn post_debug() {
        let p = make_post("dbg1", PostType::Text);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("dbg1"));
        assert!(dbg.contains("Text"));
    }

    #[test]
    fn post_no_upvote_ratio() {
        let mut p = make_post("nr1", PostType::Link);
        p.upvote_ratio = None;
        let v = serde_json::to_value(&p).unwrap();
        assert!(v["upvote_ratio"].is_null());
    }

    #[test]
    fn post_from_json() {
        let p: Post = serde_json::from_value(json!({
            "id": "json1",
            "title": "JSON Post",
            "author": "jsonuser",
            "subreddit": "test",
            "score": 7,
            "num_comments": 3,
            "created_utc": 1700000000.0,
            "permalink": "/r/test/comments/json1/",
            "nsfw": false,
            "spoiler": false,
            "locked": false,
            "archived": false,
            "post_type": "text"
        }))
        .unwrap();
        assert_eq!(p.id, "json1");
        assert_eq!(p.post_type, PostType::Text);
    }

    // ── Comment tests ───────────────────────────────────────────────

    #[test]
    fn comment_serde_roundtrip() {
        let c = make_comment("c1", 0, vec![]);
        let v = serde_json::to_value(&c).unwrap();
        let c2: Comment = serde_json::from_value(v).unwrap();
        assert_eq!(c2.id, "c1");
        assert_eq!(c2.depth, 0);
    }

    #[test]
    fn comment_with_replies() {
        let child = make_comment("child1", 1, vec![]);
        let parent = make_comment("parent1", 0, vec![child]);
        assert_eq!(parent.replies.len(), 1);
        assert_eq!(parent.replies[0].id, "child1");
    }

    #[test]
    fn comment_nested_three_levels() {
        let c2 = make_comment("c2", 2, vec![]);
        let c1 = make_comment("c1", 1, vec![c2]);
        let c0 = make_comment("c0", 0, vec![c1]);
        assert_eq!(c0.replies[0].replies[0].id, "c2");
    }

    #[test]
    fn comment_is_op() {
        let mut c = make_comment("op1", 0, vec![]);
        c.is_op = true;
        assert!(c.is_op);
    }

    #[test]
    fn comment_stickied() {
        let mut c = make_comment("st1", 0, vec![]);
        c.stickied = true;
        assert!(c.stickied);
    }

    #[test]
    fn comment_edited() {
        let mut c = make_comment("ed1", 0, vec![]);
        c.edited = Some(1_700_000_500.0);
        assert_eq!(c.edited, Some(1_700_000_500.0));
    }

    #[test]
    fn comment_with_parent_id() {
        let mut c = make_comment("p1", 1, vec![]);
        c.parent_id = Some("t3_post123".into());
        assert_eq!(c.parent_id.as_deref(), Some("t3_post123"));
    }

    #[test]
    fn comment_more_count() {
        let mut c = make_comment("mc1", 0, vec![]);
        c.more_count = Some(15);
        assert_eq!(c.more_count, Some(15));
    }

    #[test]
    fn comment_negative_score() {
        let mut c = make_comment("neg1", 0, vec![]);
        c.score = -50;
        assert_eq!(c.score, -50);
    }

    #[test]
    fn comment_clone() {
        let c = make_comment("cl1", 0, vec![make_comment("cl2", 1, vec![])]);
        let c2 = c.clone();
        assert_eq!(c.id, c2.id);
        assert_eq!(c2.replies.len(), 1);
    }

    #[test]
    fn comment_debug() {
        let c = make_comment("dbg1", 0, vec![]);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("dbg1"));
    }

    #[test]
    fn comment_default_replies() {
        let c: Comment = serde_json::from_value(json!({
            "id": "def1",
            "author": "u",
            "body": "b",
            "score": 0,
            "created_utc": 0.0,
            "depth": 0,
            "is_op": false,
            "stickied": false
        }))
        .unwrap();
        assert!(c.replies.is_empty());
    }

    // ── CommentSort tests ───────────────────────────────────────────

    #[test]
    fn comment_sort_as_str() {
        assert_eq!(CommentSort::Best.as_str(), "confidence");
        assert_eq!(CommentSort::Top.as_str(), "top");
        assert_eq!(CommentSort::New.as_str(), "new");
        assert_eq!(CommentSort::Controversial.as_str(), "controversial");
        assert_eq!(CommentSort::Old.as_str(), "old");
        assert_eq!(CommentSort::Qa.as_str(), "qa");
    }

    #[test]
    fn comment_sort_serde_roundtrip() {
        for s in [
            CommentSort::Best,
            CommentSort::Top,
            CommentSort::New,
            CommentSort::Controversial,
            CommentSort::Old,
            CommentSort::Qa,
        ] {
            let v = serde_json::to_value(s).unwrap();
            let back: CommentSort = serde_json::from_value(v).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn comment_sort_eq() {
        assert_eq!(CommentSort::Top, CommentSort::Top);
        assert_ne!(CommentSort::Top, CommentSort::New);
    }

    #[test]
    fn comment_sort_clone() {
        let s = CommentSort::Controversial;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn comment_sort_debug() {
        let dbg = format!("{:?}", CommentSort::Qa);
        assert!(dbg.contains("Qa"));
    }

    // ── CommentFetchConfig tests ────────────────────────────────────

    #[test]
    fn config_defaults() {
        let cfg = CommentFetchConfig::new();
        assert_eq!(cfg.max_comments, 200);
        assert_eq!(cfg.max_depth, 10);
        assert_eq!(cfg.sort, CommentSort::Best);
        assert!(!cfg.expand_more);
    }

    #[test]
    fn config_builder_chain() {
        let cfg = CommentFetchConfig::new()
            .with_max_comments(50)
            .with_max_depth(5)
            .with_sort(CommentSort::New)
            .with_expand_more(true);
        assert_eq!(cfg.max_comments, 50);
        assert_eq!(cfg.max_depth, 5);
        assert_eq!(cfg.sort, CommentSort::New);
        assert!(cfg.expand_more);
    }

    #[test]
    fn config_validate_ok() {
        let cfg = CommentFetchConfig::new();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_zero_comments() {
        let cfg = CommentFetchConfig::new().with_max_comments(0);
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("at least 1"));
    }

    #[test]
    fn config_validate_too_many_comments() {
        let cfg = CommentFetchConfig::new().with_max_comments(1001);
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("1001"));
        assert!(err.contains("1000"));
    }

    #[test]
    fn config_validate_depth_too_high() {
        let cfg = CommentFetchConfig::new().with_max_depth(51);
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("51"));
        assert!(err.contains("50"));
    }

    #[test]
    fn config_validate_max_boundary() {
        let cfg = CommentFetchConfig::new()
            .with_max_comments(1000)
            .with_max_depth(50);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_one_comment() {
        let cfg = CommentFetchConfig::new().with_max_comments(1);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_zero_depth() {
        let cfg = CommentFetchConfig::new().with_max_depth(0);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = CommentFetchConfig::new()
            .with_max_comments(100)
            .with_sort(CommentSort::Old);
        let v = serde_json::to_value(&cfg).unwrap();
        let cfg2: CommentFetchConfig = serde_json::from_value(v).unwrap();
        assert_eq!(cfg2.max_comments, 100);
        assert_eq!(cfg2.sort, CommentSort::Old);
    }

    #[test]
    fn config_clone() {
        let cfg = CommentFetchConfig::new().with_max_comments(77);
        let cfg2 = cfg.clone();
        assert_eq!(cfg.max_comments, cfg2.max_comments);
    }

    #[test]
    fn config_debug() {
        let cfg = CommentFetchConfig::new();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("200"));
    }

    // ── CommentTree tests ───────────────────────────────────────────

    #[test]
    fn comment_tree_empty() {
        let cfg = CommentFetchConfig::new();
        let tree = build_comment_tree("post1", &[], Some(0), &cfg);
        assert_eq!(tree.post_id, "post1");
        assert!(tree.comments.is_empty());
        assert_eq!(tree.total_loaded, 0);
        assert!(!tree.truncated);
    }

    #[test]
    fn comment_tree_single_comment() {
        let cfg = CommentFetchConfig::new();
        let c = make_comment("c1", 0, vec![]);
        let tree = build_comment_tree("post1", &[c], Some(1), &cfg);
        assert_eq!(tree.total_loaded, 1);
        assert!(!tree.truncated);
    }

    #[test]
    fn comment_tree_with_replies() {
        let cfg = CommentFetchConfig::new();
        let child = make_comment("child", 1, vec![]);
        let parent = make_comment("parent", 0, vec![child]);
        let tree = build_comment_tree("post1", &[parent], Some(2), &cfg);
        assert_eq!(tree.total_loaded, 2);
        assert!(!tree.truncated);
    }

    #[test]
    fn comment_tree_truncated_by_count() {
        let cfg = CommentFetchConfig::new().with_max_comments(2);
        let comments: Vec<Comment> = (0..5)
            .map(|i| make_comment(&format!("c{i}"), 0, vec![]))
            .collect();
        let tree = build_comment_tree("post1", &comments, Some(5), &cfg);
        assert_eq!(tree.total_loaded, 2);
        assert!(tree.truncated);
    }

    #[test]
    fn comment_tree_truncated_by_depth() {
        let cfg = CommentFetchConfig::new().with_max_depth(1);
        let grandchild = make_comment("gc", 2, vec![]);
        let child = make_comment("ch", 1, vec![grandchild]);
        let parent = make_comment("pa", 0, vec![child]);
        let tree = build_comment_tree("post1", &[parent], Some(3), &cfg);
        assert!(tree.truncated);
        // The grandchild should be removed.
        let flat = flatten_comments(&tree.comments);
        assert!(flat.iter().all(|c| c.depth <= 1));
    }

    #[test]
    fn comment_tree_total_available() {
        let cfg = CommentFetchConfig::new();
        let tree = build_comment_tree("post1", &[], Some(500), &cfg);
        assert_eq!(tree.total_available, Some(500));
    }

    #[test]
    fn comment_tree_total_available_none() {
        let cfg = CommentFetchConfig::new();
        let tree = build_comment_tree("post1", &[], None, &cfg);
        assert!(tree.total_available.is_none());
    }

    #[test]
    fn comment_tree_serde_roundtrip() {
        let cfg = CommentFetchConfig::new();
        let c = make_comment("c1", 0, vec![]);
        let tree = build_comment_tree("post1", &[c], Some(1), &cfg);
        let v = serde_json::to_value(&tree).unwrap();
        let tree2: CommentTree = serde_json::from_value(v).unwrap();
        assert_eq!(tree2.post_id, "post1");
        assert_eq!(tree2.total_loaded, 1);
    }

    #[test]
    fn comment_tree_clone() {
        let cfg = CommentFetchConfig::new();
        let tree = build_comment_tree("post1", &[], None, &cfg);
        let tree2 = tree.clone();
        assert_eq!(tree.post_id, tree2.post_id);
    }

    #[test]
    fn comment_tree_debug() {
        let cfg = CommentFetchConfig::new();
        let tree = build_comment_tree("dbg_post", &[], None, &cfg);
        let dbg = format!("{tree:?}");
        assert!(dbg.contains("dbg_post"));
    }

    // ── Bounded traversal tests ─────────────────────────────────────

    #[test]
    fn count_comments_empty() {
        assert_eq!(count_comments(&[]), 0);
    }

    #[test]
    fn count_comments_flat() {
        let comments: Vec<Comment> = (0..5)
            .map(|i| make_comment(&format!("c{i}"), 0, vec![]))
            .collect();
        assert_eq!(count_comments(&comments), 5);
    }

    #[test]
    fn count_comments_nested() {
        let c2 = make_comment("c2", 2, vec![]);
        let c1 = make_comment("c1", 1, vec![c2]);
        let c0 = make_comment("c0", 0, vec![c1]);
        assert_eq!(count_comments(&[c0]), 3);
    }

    #[test]
    fn count_comments_wide() {
        let children: Vec<Comment> = (0..10)
            .map(|i| make_comment(&format!("ch{i}"), 1, vec![]))
            .collect();
        let root = make_comment("root", 0, children);
        assert_eq!(count_comments(&[root]), 11);
    }

    #[test]
    fn max_depth_empty() {
        assert_eq!(max_depth(&[]), 0);
    }

    #[test]
    fn max_depth_flat() {
        let comments: Vec<Comment> = (0..3)
            .map(|i| make_comment(&format!("c{i}"), 0, vec![]))
            .collect();
        assert_eq!(max_depth(&comments), 0);
    }

    #[test]
    fn max_depth_nested() {
        let c2 = make_comment("c2", 2, vec![]);
        let c1 = make_comment("c1", 1, vec![c2]);
        let c0 = make_comment("c0", 0, vec![c1]);
        assert_eq!(max_depth(&[c0]), 2);
    }

    #[test]
    fn max_depth_uneven() {
        let deep = make_comment("deep", 3, vec![]);
        let mid = make_comment("mid", 2, vec![deep]);
        let branch = make_comment("branch", 1, vec![mid]);
        let shallow = make_comment("shallow", 0, vec![]);
        let root = make_comment("root", 0, vec![branch]);
        assert_eq!(max_depth(&[root, shallow]), 3);
    }

    #[test]
    fn flatten_comments_empty() {
        assert!(flatten_comments(&[]).is_empty());
    }

    #[test]
    fn flatten_comments_flat() {
        let comments: Vec<Comment> = (0..3)
            .map(|i| make_comment(&format!("c{i}"), 0, vec![]))
            .collect();
        let flat = flatten_comments(&comments);
        assert_eq!(flat.len(), 3);
    }

    #[test]
    fn flatten_comments_nested() {
        let c2 = make_comment("c2", 2, vec![]);
        let c1 = make_comment("c1", 1, vec![c2]);
        let c0 = make_comment("c0", 0, vec![c1]);
        let arr = [c0];
        let flat = flatten_comments(&arr);
        assert_eq!(flat.len(), 3);
        assert_eq!(flat[0].id, "c0");
        assert_eq!(flat[1].id, "c1");
        assert_eq!(flat[2].id, "c2");
    }

    #[test]
    fn flatten_preserves_depth_first_order() {
        let a1 = make_comment("a1", 1, vec![]);
        let a = make_comment("a", 0, vec![a1]);
        let b = make_comment("b", 0, vec![]);
        let arr = [a, b];
        let flat = flatten_comments(&arr);
        assert_eq!(flat[0].id, "a");
        assert_eq!(flat[1].id, "a1");
        assert_eq!(flat[2].id, "b");
    }

    #[test]
    fn truncate_tree_no_truncation() {
        let cfg = CommentFetchConfig::new();
        let comments = vec![make_comment("c1", 0, vec![])];
        let (result, truncated) = truncate_tree(&comments, &cfg);
        assert_eq!(result.len(), 1);
        assert!(!truncated);
    }

    #[test]
    fn truncate_tree_by_count() {
        let cfg = CommentFetchConfig::new().with_max_comments(3);
        let comments: Vec<Comment> = (0..10)
            .map(|i| make_comment(&format!("c{i}"), 0, vec![]))
            .collect();
        let (result, truncated) = truncate_tree(&comments, &cfg);
        assert_eq!(count_comments(&result), 3);
        assert!(truncated);
    }

    #[test]
    fn truncate_tree_by_depth() {
        let cfg = CommentFetchConfig::new().with_max_depth(1);
        let gc = make_comment("gc", 2, vec![]);
        let ch = make_comment("ch", 1, vec![gc]);
        let root = make_comment("root", 0, vec![ch]);
        let (result, truncated) = truncate_tree(&[root], &cfg);
        assert!(truncated);
        // ch should exist but gc should be removed.
        assert_eq!(result[0].replies.len(), 1);
        assert!(result[0].replies[0].replies.is_empty());
    }

    #[test]
    fn truncate_tree_depth_zero() {
        let cfg = CommentFetchConfig::new().with_max_depth(0);
        let child = make_comment("child", 1, vec![]);
        let root = make_comment("root", 0, vec![child]);
        let (result, truncated) = truncate_tree(&[root], &cfg);
        assert!(truncated);
        assert!(result[0].replies.is_empty());
    }

    #[test]
    fn truncate_sets_more_count() {
        let cfg = CommentFetchConfig::new().with_max_depth(0);
        let c1 = make_comment("c1", 1, vec![]);
        let c2 = make_comment("c2", 1, vec![]);
        let root = make_comment("root", 0, vec![c1, c2]);
        let (result, _) = truncate_tree(&[root], &cfg);
        // root.more_count should reflect removed children.
        assert_eq!(result[0].more_count, Some(2));
    }

    #[test]
    fn deep_chain_traversal() {
        let chain = make_deep_chain(20);
        let cfg = CommentFetchConfig::new().with_max_depth(5);
        let (result, truncated) = truncate_tree(&[chain], &cfg);
        assert!(truncated);
        let flat = flatten_comments(&result);
        assert!(flat.iter().all(|c| c.depth <= 5));
    }

    // ── ContentBounds tests ─────────────────────────────────────────

    #[test]
    fn content_bounds_defaults() {
        let b = ContentBounds::default();
        assert_eq!(b.max_selftext_length, 40_000);
        assert_eq!(b.max_comment_body_length, 10_000);
        assert_eq!(b.max_history_items, 100);
    }

    #[test]
    fn truncate_text_short() {
        let result = ContentBounds::truncate_text("hello", 10);
        assert_eq!(result, "hello");
    }

    #[test]
    fn truncate_text_exact_boundary() {
        let result = ContentBounds::truncate_text("hello", 5);
        assert_eq!(result, "hello");
    }

    #[test]
    fn truncate_text_over_limit() {
        let result = ContentBounds::truncate_text("hello world", 5);
        assert_eq!(result, "hello...");
    }

    #[test]
    fn truncate_text_multibyte_char() {
        // The char takes 2 bytes so truncating at 1 should back up.
        let result = ContentBounds::truncate_text("\u{00e9}test", 1);
        assert!(result.is_char_boundary(0));
        assert_eq!(result, "...");
    }

    #[test]
    fn truncate_text_emoji() {
        // Emoji is 4 bytes. Truncating at 2 should back up to 0.
        let result = ContentBounds::truncate_text("\u{1f600}abc", 2);
        assert_eq!(result, "...");
    }

    #[test]
    fn truncate_text_after_emoji() {
        let result = ContentBounds::truncate_text("\u{1f600}abc", 6);
        // 4 bytes for emoji + 'a' = 5, then we need 6, but total is 7 so truncation at 6.
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_text_empty() {
        let result = ContentBounds::truncate_text("", 10);
        assert_eq!(result, "");
    }

    #[test]
    fn truncate_text_zero_limit() {
        let result = ContentBounds::truncate_text("hello", 0);
        assert_eq!(result, "...");
    }

    #[test]
    fn truncate_text_one_char() {
        let result = ContentBounds::truncate_text("abcdef", 1);
        assert_eq!(result, "a...");
    }

    #[test]
    fn content_bounds_serde_roundtrip() {
        let b = ContentBounds::default();
        let v = serde_json::to_value(&b).unwrap();
        let b2: ContentBounds = serde_json::from_value(v).unwrap();
        assert_eq!(b2.max_selftext_length, 40_000);
    }

    #[test]
    fn content_bounds_clone() {
        let b = ContentBounds::default();
        let b2 = b.clone();
        assert_eq!(b.max_selftext_length, b2.max_selftext_length);
    }

    #[test]
    fn content_bounds_debug() {
        let b = ContentBounds::default();
        let dbg = format!("{b:?}");
        assert!(dbg.contains("40000"));
    }

    // ── apply_bounds tests ──────────────────────────────────────────

    #[test]
    fn apply_bounds_to_post_no_truncation() {
        let mut p = make_post("p1", PostType::Text);
        let bounds = ContentBounds::default();
        apply_bounds_to_post(&mut p, &bounds);
        assert_eq!(p.selftext.as_deref(), Some("Hello world"));
    }

    #[test]
    fn apply_bounds_to_post_truncates_long_text() {
        let mut p = make_post("p2", PostType::Text);
        p.selftext = Some("x".repeat(50_000));
        let bounds = ContentBounds::default();
        apply_bounds_to_post(&mut p, &bounds);
        let text = p.selftext.unwrap();
        assert!(text.len() < 50_000);
        assert!(text.ends_with("..."));
    }

    #[test]
    fn apply_bounds_to_post_no_selftext() {
        let mut p = make_post("p3", PostType::Link);
        p.selftext = None;
        let bounds = ContentBounds::default();
        apply_bounds_to_post(&mut p, &bounds);
        assert!(p.selftext.is_none());
    }

    #[test]
    fn apply_bounds_to_comments_no_truncation() {
        let mut comments = vec![make_comment("c1", 0, vec![])];
        let bounds = ContentBounds::default();
        apply_bounds_to_comments(&mut comments, &bounds);
        assert_eq!(comments[0].body, "Comment c1");
    }

    #[test]
    fn apply_bounds_to_comments_truncates_body() {
        let mut c = make_comment("c1", 0, vec![]);
        c.body = "y".repeat(20_000);
        let mut comments = vec![c];
        let bounds = ContentBounds::default();
        apply_bounds_to_comments(&mut comments, &bounds);
        assert!(comments[0].body.len() < 20_000);
        assert!(comments[0].body.ends_with("..."));
    }

    #[test]
    fn apply_bounds_to_comments_nested() {
        let mut child = make_comment("child", 1, vec![]);
        child.body = "z".repeat(15_000);
        let parent = make_comment("parent", 0, vec![child]);
        let mut comments = vec![parent];
        let bounds = ContentBounds::default();
        apply_bounds_to_comments(&mut comments, &bounds);
        assert!(comments[0].replies[0].body.ends_with("..."));
    }

    // ── UserHistory / PostSummary / UserComment tests ───────────────

    #[test]
    fn post_summary_serde_roundtrip() {
        let ps = PostSummary {
            id: "t3_sum1".into(),
            title: "Summary".into(),
            subreddit: "test".into(),
            score: 99,
            num_comments: 10,
            created_utc: 1_700_000_000.0,
        };
        let v = serde_json::to_value(&ps).unwrap();
        let ps2: PostSummary = serde_json::from_value(v).unwrap();
        assert_eq!(ps2.id, "t3_sum1");
        assert_eq!(ps2.score, 99);
    }

    #[test]
    fn post_summary_clone() {
        let ps = PostSummary {
            id: "t3_cl".into(),
            title: "Clone".into(),
            subreddit: "test".into(),
            score: 1,
            num_comments: 0,
            created_utc: 0.0,
        };
        let ps2 = ps.clone();
        assert_eq!(ps.id, ps2.id);
    }

    #[test]
    fn post_summary_debug() {
        let ps = PostSummary {
            id: "t3_dbg".into(),
            title: "Debug".into(),
            subreddit: "test".into(),
            score: 0,
            num_comments: 0,
            created_utc: 0.0,
        };
        let dbg = format!("{ps:?}");
        assert!(dbg.contains("t3_dbg"));
    }

    #[test]
    fn user_comment_serde_roundtrip() {
        let uc = UserComment {
            id: "t1_uc1".into(),
            body: "User comment".into(),
            subreddit: "rust".into(),
            post_title: Some("Post title".into()),
            score: 5,
            created_utc: 1_700_000_200.0,
            permalink: "/r/rust/comments/x/y/uc1/".into(),
        };
        let v = serde_json::to_value(&uc).unwrap();
        let uc2: UserComment = serde_json::from_value(v).unwrap();
        assert_eq!(uc2.id, "t1_uc1");
        assert_eq!(uc2.post_title.as_deref(), Some("Post title"));
    }

    #[test]
    fn user_comment_no_post_title() {
        let uc = UserComment {
            id: "t1_nt".into(),
            body: "body".into(),
            subreddit: "test".into(),
            post_title: None,
            score: 0,
            created_utc: 0.0,
            permalink: "/r/test/".into(),
        };
        let v = serde_json::to_value(&uc).unwrap();
        assert!(v["post_title"].is_null());
    }

    #[test]
    fn user_comment_clone() {
        let uc = UserComment {
            id: "t1_cl".into(),
            body: "clone".into(),
            subreddit: "test".into(),
            post_title: None,
            score: 0,
            created_utc: 0.0,
            permalink: "/".into(),
        };
        let uc2 = uc.clone();
        assert_eq!(uc.id, uc2.id);
    }

    #[test]
    fn user_comment_debug() {
        let uc = UserComment {
            id: "t1_dbg".into(),
            body: "debug".into(),
            subreddit: "test".into(),
            post_title: None,
            score: 0,
            created_utc: 0.0,
            permalink: "/".into(),
        };
        let dbg = format!("{uc:?}");
        assert!(dbg.contains("t1_dbg"));
    }

    #[test]
    fn user_history_serde_roundtrip() {
        let uh = UserHistory {
            username: "testuser".into(),
            posts: vec![PostSummary {
                id: "t3_h1".into(),
                title: "History Post".into(),
                subreddit: "rust".into(),
                score: 10,
                num_comments: 2,
                created_utc: 1_700_000_000.0,
            }],
            comments: vec![UserComment {
                id: "t1_h1".into(),
                body: "History comment".into(),
                subreddit: "rust".into(),
                post_title: Some("Parent".into()),
                score: 3,
                created_utc: 1_700_000_100.0,
                permalink: "/r/rust/comments/x/y/h1/".into(),
            }],
            total_karma: Some(1000),
        };
        let v = serde_json::to_value(&uh).unwrap();
        let uh2: UserHistory = serde_json::from_value(v).unwrap();
        assert_eq!(uh2.username, "testuser");
        assert_eq!(uh2.posts.len(), 1);
        assert_eq!(uh2.comments.len(), 1);
        assert_eq!(uh2.total_karma, Some(1000));
    }

    #[test]
    fn user_history_empty() {
        let uh = UserHistory {
            username: "empty".into(),
            posts: vec![],
            comments: vec![],
            total_karma: None,
        };
        assert!(uh.posts.is_empty());
        assert!(uh.comments.is_empty());
        assert!(uh.total_karma.is_none());
    }

    #[test]
    fn user_history_clone() {
        let uh = UserHistory {
            username: "cl".into(),
            posts: vec![],
            comments: vec![],
            total_karma: Some(42),
        };
        let uh2 = uh.clone();
        assert_eq!(uh.username, uh2.username);
        assert_eq!(uh2.total_karma, Some(42));
    }

    #[test]
    fn user_history_debug() {
        let uh = UserHistory {
            username: "dbg_user".into(),
            posts: vec![],
            comments: vec![],
            total_karma: None,
        };
        let dbg = format!("{uh:?}");
        assert!(dbg.contains("dbg_user"));
    }

    // ── apply_bounds_to_history tests ───────────────────────────────

    #[test]
    fn apply_bounds_to_history_no_truncation() {
        let mut uh = UserHistory {
            username: "user".into(),
            posts: vec![PostSummary {
                id: "t3_1".into(),
                title: "P".into(),
                subreddit: "t".into(),
                score: 0,
                num_comments: 0,
                created_utc: 0.0,
            }],
            comments: vec![],
            total_karma: None,
        };
        let bounds = ContentBounds::default();
        apply_bounds_to_history(&mut uh, &bounds);
        assert_eq!(uh.posts.len(), 1);
    }

    #[test]
    fn apply_bounds_to_history_truncates_items() {
        let mut uh = UserHistory {
            username: "user".into(),
            posts: (0..150)
                .map(|i| PostSummary {
                    id: format!("t3_{i}"),
                    title: format!("Post {i}"),
                    subreddit: "t".into(),
                    score: 0,
                    num_comments: 0,
                    created_utc: 0.0,
                })
                .collect(),
            comments: (0..150)
                .map(|i| UserComment {
                    id: format!("t1_{i}"),
                    body: format!("Comment {i}"),
                    subreddit: "t".into(),
                    post_title: None,
                    score: 0,
                    created_utc: 0.0,
                    permalink: "/".into(),
                })
                .collect(),
            total_karma: Some(500),
        };
        let bounds = ContentBounds::default();
        apply_bounds_to_history(&mut uh, &bounds);
        assert_eq!(uh.posts.len(), 100);
        assert_eq!(uh.comments.len(), 100);
    }

    #[test]
    fn apply_bounds_to_history_truncates_comment_body() {
        let mut uh = UserHistory {
            username: "user".into(),
            posts: vec![],
            comments: vec![UserComment {
                id: "t1_long".into(),
                body: "q".repeat(20_000),
                subreddit: "t".into(),
                post_title: None,
                score: 0,
                created_utc: 0.0,
                permalink: "/".into(),
            }],
            total_karma: None,
        };
        let bounds = ContentBounds::default();
        apply_bounds_to_history(&mut uh, &bounds);
        assert!(uh.comments[0].body.len() < 20_000);
        assert!(uh.comments[0].body.ends_with("..."));
    }

    #[test]
    fn apply_bounds_custom_limits() {
        let bounds = ContentBounds {
            max_selftext_length: 100,
            max_comment_body_length: 50,
            max_history_items: 5,
        };
        let mut uh = UserHistory {
            username: "user".into(),
            posts: (0..10)
                .map(|i| PostSummary {
                    id: format!("t3_{i}"),
                    title: "T".into(),
                    subreddit: "t".into(),
                    score: 0,
                    num_comments: 0,
                    created_utc: 0.0,
                })
                .collect(),
            comments: vec![],
            total_karma: None,
        };
        apply_bounds_to_history(&mut uh, &bounds);
        assert_eq!(uh.posts.len(), 5);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn very_large_comment_tree() {
        // Build a tree with many siblings and nested children.
        let mut comments = Vec::new();
        for i in 0..20 {
            let children: Vec<Comment> = (0..5)
                .map(|j| make_comment(&format!("c{i}_{j}"), 1, vec![]))
                .collect();
            comments.push(make_comment(&format!("r{i}"), 0, children));
        }
        let cfg = CommentFetchConfig::new().with_max_comments(50);
        let tree = build_comment_tree("large", &comments, Some(120), &cfg);
        assert!(tree.total_loaded <= 50);
        assert!(tree.truncated);
    }

    #[test]
    fn comment_tree_max_depth_reached_flag() {
        let cfg = CommentFetchConfig::new().with_max_depth(2);
        let c2 = make_comment("c2", 2, vec![]);
        let c1 = make_comment("c1", 1, vec![c2]);
        let c0 = make_comment("c0", 0, vec![c1]);
        let tree = build_comment_tree("dp", &[c0], Some(3), &cfg);
        assert!(tree.max_depth_reached);
    }

    #[test]
    fn comment_tree_max_depth_not_reached() {
        let cfg = CommentFetchConfig::new().with_max_depth(10);
        let c = make_comment("c0", 0, vec![]);
        let tree = build_comment_tree("dp", &[c], Some(1), &cfg);
        assert!(!tree.max_depth_reached);
    }

    #[test]
    fn post_type_from_json_all_variants() {
        let variants = [
            ("text", PostType::Text),
            ("link", PostType::Link),
            ("image", PostType::Image),
            ("video", PostType::Video),
            ("gallery", PostType::Gallery),
            ("poll", PostType::Poll),
            ("crosspost", PostType::Crosspost),
            ("unknown", PostType::Unknown),
        ];
        for (s, expected) in variants {
            let pt: PostType = serde_json::from_value(json!(s)).unwrap();
            assert_eq!(pt, expected);
        }
    }

    #[test]
    fn comment_sort_from_json_all_variants() {
        let variants = [
            ("best", CommentSort::Best),
            ("top", CommentSort::Top),
            ("new", CommentSort::New),
            ("controversial", CommentSort::Controversial),
            ("old", CommentSort::Old),
            ("qa", CommentSort::Qa),
        ];
        for (s, expected) in variants {
            let cs: CommentSort = serde_json::from_value(json!(s)).unwrap();
            assert_eq!(cs, expected);
        }
    }

    #[test]
    fn truncate_text_ascii_boundary() {
        let text = "abcdefghij"; // 10 bytes, all ASCII.
        let result = ContentBounds::truncate_text(text, 7);
        assert_eq!(result, "abcdefg...");
    }

    #[test]
    fn truncate_text_cyrillic() {
        // Each Cyrillic char is 2 bytes.
        let text = "\u{0410}\u{0411}\u{0412}\u{0413}"; // 8 bytes.
        let result = ContentBounds::truncate_text(text, 5);
        // Should back up to byte 4 (end of second char).
        assert_eq!(result, "\u{0410}\u{0411}...");
    }

    #[test]
    fn truncate_text_cjk() {
        // Each CJK char is 3 bytes.
        let text = "\u{4e00}\u{4e8c}\u{4e09}"; // 9 bytes.
        let result = ContentBounds::truncate_text(text, 4);
        // Byte 4 is mid-char, back up to 3 (end of first char).
        assert_eq!(result, "\u{4e00}...");
    }

    #[test]
    fn post_with_all_optional_fields_null() {
        let p: Post = serde_json::from_value(json!({
            "id": "t3_null",
            "title": "Null fields",
            "author": "u",
            "subreddit": "t",
            "selftext": null,
            "url": null,
            "score": 0,
            "upvote_ratio": null,
            "num_comments": 0,
            "created_utc": 0.0,
            "edited": null,
            "permalink": "/r/t/",
            "link_flair_text": null,
            "nsfw": false,
            "spoiler": false,
            "locked": false,
            "archived": false,
            "post_type": "text"
        }))
        .unwrap();
        assert!(p.selftext.is_none());
        assert!(p.url.is_none());
        assert!(p.upvote_ratio.is_none());
        assert!(p.edited.is_none());
        assert!(p.link_flair_text.is_none());
    }

    #[test]
    fn content_bounds_custom_values() {
        let b = ContentBounds {
            max_selftext_length: 500,
            max_comment_body_length: 200,
            max_history_items: 10,
        };
        assert_eq!(b.max_selftext_length, 500);
        assert_eq!(b.max_comment_body_length, 200);
        assert_eq!(b.max_history_items, 10);
    }

    #[test]
    fn user_history_negative_karma() {
        let uh = UserHistory {
            username: "troll".into(),
            posts: vec![],
            comments: vec![],
            total_karma: Some(-100),
        };
        assert_eq!(uh.total_karma, Some(-100));
    }

    #[test]
    fn user_history_large_karma() {
        let uh = UserHistory {
            username: "veteran".into(),
            posts: vec![],
            comments: vec![],
            total_karma: Some(1_000_000),
        };
        assert_eq!(uh.total_karma, Some(1_000_000));
    }

    #[test]
    fn post_summary_negative_score() {
        let ps = PostSummary {
            id: "t3_neg".into(),
            title: "Negative".into(),
            subreddit: "test".into(),
            score: -42,
            num_comments: 0,
            created_utc: 0.0,
        };
        assert_eq!(ps.score, -42);
    }

    #[test]
    fn user_comment_negative_score() {
        let uc = UserComment {
            id: "t1_neg".into(),
            body: "bad".into(),
            subreddit: "t".into(),
            post_title: None,
            score: -25,
            created_utc: 0.0,
            permalink: "/".into(),
        };
        assert_eq!(uc.score, -25);
    }
}
