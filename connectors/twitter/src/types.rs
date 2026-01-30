//! Twitter API v2 types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Core Response Wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// Standard Twitter API v2 response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwitterResponse<T> {
    /// The primary data
    #[serde(default)]
    pub data: Option<T>,

    /// Included expansions (users, tweets, media, etc.)
    #[serde(default)]
    pub includes: Option<Includes>,

    /// Metadata about the response
    #[serde(default)]
    pub meta: Option<ResponseMeta>,

    /// Errors (partial failures)
    #[serde(default)]
    pub errors: Option<Vec<TwitterApiError>>,
}

/// Included expansions in Twitter API responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Includes {
    /// Expanded user objects
    #[serde(default)]
    pub users: Vec<User>,

    /// Expanded tweet objects
    #[serde(default)]
    pub tweets: Vec<Tweet>,

    /// Expanded media objects
    #[serde(default)]
    pub media: Vec<Media>,

    /// Expanded place objects
    #[serde(default)]
    pub places: Vec<Place>,

    /// Expanded poll objects
    #[serde(default)]
    pub polls: Vec<Poll>,
}

/// Response metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMeta {
    /// Number of results
    #[serde(default)]
    pub result_count: Option<u32>,

    /// Token for next page
    #[serde(default)]
    pub next_token: Option<String>,

    /// Token for previous page
    #[serde(default)]
    pub previous_token: Option<String>,

    /// Newest tweet ID in the response
    #[serde(default)]
    pub newest_id: Option<String>,

    /// Oldest tweet ID in the response
    #[serde(default)]
    pub oldest_id: Option<String>,
}

/// Twitter API error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwitterApiError {
    /// Error title
    #[serde(default)]
    pub title: Option<String>,

    /// Error detail
    #[serde(default)]
    pub detail: Option<String>,

    /// Error type
    #[serde(default, rename = "type")]
    pub error_type: Option<String>,

    /// Resource type (e.g., "tweet", "user")
    #[serde(default)]
    pub resource_type: Option<String>,

    /// Resource ID that caused the error
    #[serde(default)]
    pub resource_id: Option<String>,

    /// Parameter that caused the error
    #[serde(default)]
    pub parameter: Option<String>,

    /// Field path that caused the error
    #[serde(default)]
    pub field: Option<String>,

    /// Section of the request
    #[serde(default)]
    pub section: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tweet Types
// ─────────────────────────────────────────────────────────────────────────────

/// Twitter tweet object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tweet {
    /// Tweet ID
    pub id: String,

    /// Tweet text content
    pub text: String,

    /// Author user ID
    #[serde(default)]
    pub author_id: Option<String>,

    /// Tweet creation timestamp (ISO 8601)
    #[serde(default)]
    pub created_at: Option<String>,

    /// Conversation ID (ID of the original tweet in a thread)
    #[serde(default)]
    pub conversation_id: Option<String>,

    /// ID of the tweet this is replying to
    #[serde(default)]
    pub in_reply_to_user_id: Option<String>,

    /// Referenced tweets (replies, quotes, retweets)
    #[serde(default)]
    pub referenced_tweets: Option<Vec<ReferencedTweet>>,

    /// Attached media keys
    #[serde(default)]
    pub attachments: Option<Attachments>,

    /// Public engagement metrics
    #[serde(default)]
    pub public_metrics: Option<TweetPublicMetrics>,

    /// Tweet context annotations
    #[serde(default)]
    pub context_annotations: Option<Vec<ContextAnnotation>>,

    /// Entities (mentions, hashtags, URLs, etc.)
    #[serde(default)]
    pub entities: Option<Entities>,

    /// Language of the tweet (BCP47)
    #[serde(default)]
    pub lang: Option<String>,

    /// Source application
    #[serde(default)]
    pub source: Option<String>,

    /// Whether the tweet may contain sensitive content
    #[serde(default)]
    pub possibly_sensitive: Option<bool>,

    /// Reply settings
    #[serde(default)]
    pub reply_settings: Option<String>,

    /// Edit history tweet IDs
    #[serde(default)]
    pub edit_history_tweet_ids: Option<Vec<String>>,
}

/// Referenced tweet (retweet, quote, reply).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferencedTweet {
    /// Reference type: "retweeted", "quoted", "`replied_to`"
    #[serde(rename = "type")]
    pub ref_type: String,

    /// Referenced tweet ID
    pub id: String,
}

/// Tweet attachments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachments {
    /// Media keys
    #[serde(default)]
    pub media_keys: Option<Vec<String>>,

    /// Poll IDs
    #[serde(default)]
    pub poll_ids: Option<Vec<String>>,
}

/// Tweet public metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TweetPublicMetrics {
    /// Retweet count
    pub retweet_count: u64,

    /// Reply count
    pub reply_count: u64,

    /// Like count
    pub like_count: u64,

    /// Quote count
    pub quote_count: u64,

    /// Bookmark count
    #[serde(default)]
    pub bookmark_count: Option<u64>,

    /// Impression count
    #[serde(default)]
    pub impression_count: Option<u64>,
}

/// Context annotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAnnotation {
    /// Domain information
    pub domain: ContextAnnotationDomain,

    /// Entity information
    pub entity: ContextAnnotationEntity,
}

/// Context annotation domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAnnotationDomain {
    /// Domain ID
    pub id: String,

    /// Domain name
    pub name: String,

    /// Domain description
    #[serde(default)]
    pub description: Option<String>,
}

/// Context annotation entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAnnotationEntity {
    /// Entity ID
    pub id: String,

    /// Entity name
    pub name: String,

    /// Entity description
    #[serde(default)]
    pub description: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// User Types
// ─────────────────────────────────────────────────────────────────────────────

/// Twitter user object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct User {
    /// User ID
    pub id: String,

    /// Display name
    pub name: String,

    /// Username (handle without @)
    pub username: String,

    /// User bio
    #[serde(default)]
    pub description: Option<String>,

    /// Profile image URL
    #[serde(default)]
    pub profile_image_url: Option<String>,

    /// User location
    #[serde(default)]
    pub location: Option<String>,

    /// User URL
    #[serde(default)]
    pub url: Option<String>,

    /// Whether the account is verified
    #[serde(default)]
    pub verified: Option<bool>,

    /// Verification type
    #[serde(default)]
    pub verified_type: Option<String>,

    /// Whether the account is protected (private)
    #[serde(default)]
    pub protected: Option<bool>,

    /// Account creation timestamp
    #[serde(default)]
    pub created_at: Option<String>,

    /// Public metrics
    #[serde(default)]
    pub public_metrics: Option<UserPublicMetrics>,

    /// Pinned tweet ID
    #[serde(default)]
    pub pinned_tweet_id: Option<String>,

    /// Entities in user fields
    #[serde(default)]
    pub entities: Option<UserEntities>,
}

/// User public metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublicMetrics {
    /// Followers count
    pub followers_count: u64,

    /// Following count
    pub following_count: u64,

    /// Tweet count
    pub tweet_count: u64,

    /// Listed count
    pub listed_count: u64,

    /// Like count (if available)
    #[serde(default)]
    pub like_count: Option<u64>,
}

/// User entities (URLs in bio, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntities {
    /// URL entities
    #[serde(default)]
    pub url: Option<EntityUrls>,

    /// Description entities
    #[serde(default)]
    pub description: Option<EntityUrls>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Entity Types
// ─────────────────────────────────────────────────────────────────────────────

/// Tweet entities (mentions, hashtags, URLs, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Entities {
    /// Hashtags
    #[serde(default)]
    pub hashtags: Option<Vec<Hashtag>>,

    /// Mentions
    #[serde(default)]
    pub mentions: Option<Vec<Mention>>,

    /// URLs
    #[serde(default)]
    pub urls: Option<Vec<UrlEntity>>,

    /// Cashtags
    #[serde(default)]
    pub cashtags: Option<Vec<Cashtag>>,

    /// Annotations
    #[serde(default)]
    pub annotations: Option<Vec<Annotation>>,
}

/// Entity URLs wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityUrls {
    /// URL entities
    #[serde(default)]
    pub urls: Vec<UrlEntity>,
}

/// Hashtag entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hashtag {
    /// Hashtag text (without #)
    pub tag: String,

    /// Start position in text
    pub start: u32,

    /// End position in text
    pub end: u32,
}

/// Mention entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mention {
    /// Mentioned username
    pub username: String,

    /// Start position in text
    pub start: u32,

    /// End position in text
    pub end: u32,

    /// Mentioned user ID
    #[serde(default)]
    pub id: Option<String>,
}

/// URL entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlEntity {
    /// Original URL in tweet
    pub url: String,

    /// Expanded URL
    #[serde(default)]
    pub expanded_url: Option<String>,

    /// Display URL
    #[serde(default)]
    pub display_url: Option<String>,

    /// Unwound URL (final destination after redirects)
    #[serde(default)]
    pub unwound_url: Option<String>,

    /// Start position in text
    pub start: u32,

    /// End position in text
    pub end: u32,

    /// HTTP status of the URL
    #[serde(default)]
    pub status: Option<u32>,

    /// Title of the linked page
    #[serde(default)]
    pub title: Option<String>,

    /// Description of the linked page
    #[serde(default)]
    pub description: Option<String>,

    /// Media key if this URL is a media attachment
    #[serde(default)]
    pub media_key: Option<String>,
}

/// Cashtag entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cashtag {
    /// Cashtag text (without $)
    pub tag: String,

    /// Start position in text
    pub start: u32,

    /// End position in text
    pub end: u32,
}

/// Annotation entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    /// Annotation type
    #[serde(rename = "type")]
    pub annotation_type: String,

    /// Normalized text
    pub normalized_text: String,

    /// Probability score
    pub probability: f64,

    /// Start position in text
    pub start: u32,

    /// End position in text
    pub end: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Media Types
// ─────────────────────────────────────────────────────────────────────────────

/// Media object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Media {
    /// Media key
    pub media_key: String,

    /// Media type: "photo", "video", "`animated_gif`"
    #[serde(rename = "type")]
    pub media_type: String,

    /// URL (for photos)
    #[serde(default)]
    pub url: Option<String>,

    /// Preview image URL
    #[serde(default)]
    pub preview_image_url: Option<String>,

    /// Width in pixels
    #[serde(default)]
    pub width: Option<u32>,

    /// Height in pixels
    #[serde(default)]
    pub height: Option<u32>,

    /// Duration in milliseconds (for video)
    #[serde(default)]
    pub duration_ms: Option<u64>,

    /// Alt text
    #[serde(default)]
    pub alt_text: Option<String>,

    /// View count (for video)
    #[serde(default)]
    pub public_metrics: Option<MediaPublicMetrics>,
}

/// Media public metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaPublicMetrics {
    /// View count
    pub view_count: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Place Types
// ─────────────────────────────────────────────────────────────────────────────

/// Place object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Place {
    /// Place ID
    pub id: String,

    /// Full name (e.g., "San Francisco, CA")
    pub full_name: String,

    /// Place name
    #[serde(default)]
    pub name: Option<String>,

    /// Country
    #[serde(default)]
    pub country: Option<String>,

    /// Country code
    #[serde(default)]
    pub country_code: Option<String>,

    /// Place type
    #[serde(default)]
    pub place_type: Option<String>,

    /// Geo bounding box
    #[serde(default)]
    pub geo: Option<PlaceGeo>,
}

/// Place geo information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceGeo {
    /// Geometry type
    #[serde(rename = "type")]
    pub geo_type: String,

    /// Bounding box coordinates
    pub bbox: Vec<f64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Poll Types
// ─────────────────────────────────────────────────────────────────────────────

/// Poll object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Poll {
    /// Poll ID
    pub id: String,

    /// Poll options
    pub options: Vec<PollOption>,

    /// Voting status
    #[serde(default)]
    pub voting_status: Option<String>,

    /// End datetime
    #[serde(default)]
    pub end_datetime: Option<String>,

    /// Duration in minutes
    #[serde(default)]
    pub duration_minutes: Option<u32>,
}

/// Poll option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollOption {
    /// Option position
    pub position: u32,

    /// Option label
    pub label: String,

    /// Vote count
    pub votes: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Request Types
// ─────────────────────────────────────────────────────────────────────────────

/// Create tweet request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateTweetRequest {
    /// Tweet text (required unless media is attached)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Reply settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<TweetReply>,

    /// Quote tweet ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_tweet_id: Option<String>,

    /// Media attachments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<TweetMedia>,

    /// Poll
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll: Option<TweetPoll>,

    /// Reply settings: "everyone", "mentionedUsers", "following"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_settings: Option<String>,

    /// Direct message deep link
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_message_deep_link: Option<String>,

    /// Geographic location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<TweetGeo>,

    /// Exclude reply user IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub for_super_followers_only: Option<bool>,
}

/// Tweet reply settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TweetReply {
    /// ID of tweet being replied to
    pub in_reply_to_tweet_id: String,

    /// User IDs to exclude from reply
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_reply_user_ids: Option<Vec<String>>,
}

/// Tweet media attachments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TweetMedia {
    /// Media IDs
    pub media_ids: Vec<String>,

    /// Tagged user IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tagged_user_ids: Option<Vec<String>>,
}

/// Tweet poll settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TweetPoll {
    /// Poll options (2-4)
    pub options: Vec<String>,

    /// Poll duration in minutes (5-10080)
    pub duration_minutes: u32,
}

/// Tweet geo settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TweetGeo {
    /// Place ID
    pub place_id: String,
}

/// Create tweet response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTweetResponse {
    /// Created tweet data
    pub data: CreatedTweet,
}

/// Created tweet data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedTweet {
    /// Tweet ID
    pub id: String,

    /// Tweet text
    pub text: String,

    /// Edit history tweet IDs
    #[serde(default)]
    pub edit_history_tweet_ids: Option<Vec<String>>,
}

/// Delete tweet response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteTweetResponse {
    /// Deletion data
    pub data: DeletedTweet,
}

/// Deleted tweet data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedTweet {
    /// Whether deletion was successful
    pub deleted: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Search Types
// ─────────────────────────────────────────────────────────────────────────────

/// Search tweets query parameters.
#[derive(Debug, Clone, Default)]
pub struct SearchTweetsParams {
    /// Search query (required)
    pub query: String,

    /// Maximum results per page (10-100)
    pub max_results: Option<u32>,

    /// Pagination token for next page
    pub next_token: Option<String>,

    /// Return tweets created after this ID
    pub since_id: Option<String>,

    /// Return tweets created before this ID
    pub until_id: Option<String>,

    /// Start time (ISO 8601)
    pub start_time: Option<String>,

    /// End time (ISO 8601)
    pub end_time: Option<String>,

    /// Sort order: "recency" or "relevancy"
    pub sort_order: Option<String>,

    /// Tweet fields to include
    pub tweet_fields: Option<Vec<String>>,

    /// User fields to include
    pub user_fields: Option<Vec<String>>,

    /// Media fields to include
    pub media_fields: Option<Vec<String>>,

    /// Expansions to include
    pub expansions: Option<Vec<String>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Stream Types
// ─────────────────────────────────────────────────────────────────────────────

/// Filtered stream rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRule {
    /// Rule ID
    #[serde(default)]
    pub id: Option<String>,

    /// Rule value (query)
    pub value: String,

    /// Rule tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// Add stream rules request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddStreamRulesRequest {
    /// Rules to add
    pub add: Vec<StreamRule>,
}

/// Delete stream rules request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteStreamRulesRequest {
    /// Rules to delete
    pub delete: DeleteRulesSpec,
}

/// Delete rules specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRulesSpec {
    /// Rule IDs to delete
    pub ids: Vec<String>,
}

/// Stream rules response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRulesResponse {
    /// Rules
    #[serde(default)]
    pub data: Option<Vec<StreamRule>>,

    /// Metadata
    #[serde(default)]
    pub meta: Option<StreamRulesMeta>,

    /// Errors
    #[serde(default)]
    pub errors: Option<Vec<TwitterApiError>>,
}

/// Stream rules metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRulesMeta {
    /// Timestamp
    pub sent: String,

    /// Summary of changes
    #[serde(default)]
    pub summary: Option<RulesSummary>,
}

/// Rules change summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesSummary {
    /// Number of rules created
    #[serde(default)]
    pub created: Option<u32>,

    /// Number of rules not created
    #[serde(default)]
    pub not_created: Option<u32>,

    /// Number of rules deleted
    #[serde(default)]
    pub deleted: Option<u32>,

    /// Number of rules not deleted
    #[serde(default)]
    pub not_deleted: Option<u32>,

    /// Number of valid rules
    #[serde(default)]
    pub valid: Option<u32>,

    /// Number of invalid rules
    #[serde(default)]
    pub invalid: Option<u32>,
}

/// Stream tweet event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamTweet {
    /// Tweet data
    pub data: Tweet,

    /// Included expansions
    #[serde(default)]
    pub includes: Option<Includes>,

    /// Matching rules
    #[serde(default)]
    pub matching_rules: Option<Vec<MatchingRule>>,
}

/// Matching rule for stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchingRule {
    /// Rule ID
    pub id: String,

    /// Rule tag
    #[serde(default)]
    pub tag: Option<String>,
}
