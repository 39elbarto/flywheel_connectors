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
// Retweet / Like Response Types
// ─────────────────────────────────────────────────────────────────────────────

/// Retweet response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetweetResponse {
    /// Retweet data
    pub data: RetweetData,
}

/// Retweet data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetweetData {
    /// Whether the retweet was successful
    pub retweeted: bool,
}

/// Unretweet response (same shape as delete).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnretweetResponse {
    /// Unretweet data
    pub data: RetweetData,
}

/// Like response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LikeResponse {
    /// Like data
    pub data: LikeData,
}

/// Like data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LikeData {
    /// Whether the like was successful
    pub liked: bool,
}

/// Unlike response (same shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlikeResponse {
    /// Unlike data
    pub data: LikeData,
}

// ─────────────────────────────────────────────────────────────────────────────
// Direct Message Types
// ─────────────────────────────────────────────────────────────────────────────

/// DM event object (Twitter API v2 DM format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmEvent {
    /// Event ID
    pub id: String,

    /// Event type: "`MessageCreate`"
    pub event_type: String,

    /// Message text
    #[serde(default)]
    pub text: Option<String>,

    /// Sender ID
    #[serde(default)]
    pub sender_id: Option<String>,

    /// DM conversation ID
    #[serde(default)]
    pub dm_conversation_id: Option<String>,

    /// Creation timestamp (ISO 8601)
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Request body to create a DM in an existing conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendDmRequest {
    /// Message text
    pub text: String,
}

/// Response from creating a DM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendDmResponse {
    /// DM event data
    pub data: SentDmData,
}

/// Sent DM data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentDmData {
    /// The DM conversation ID
    pub dm_conversation_id: String,

    /// The DM event ID
    pub dm_event_id: String,
}

/// Request body to create a new DM conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDmConversationRequest {
    /// Conversation type (always "Group" for new convos)
    pub conversation_type: String,

    /// Participant IDs
    pub participant_ids: Vec<String>,

    /// Initial message
    pub message: SendDmRequest,
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
// Trends Types
// ─────────────────────────────────────────────────────────────────────────────

/// A trending topic entry from the trends/place endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trend {
    /// Display name of the trend (for example, "#Rust").
    pub name: String,

    /// URL to the trend page.
    pub url: String,

    /// Query string representation of the trend.
    pub query: String,

    /// Promoted content indicator.
    #[serde(default)]
    pub promoted_content: Option<String>,

    /// Estimated tweet volume when available.
    #[serde(default)]
    pub tweet_volume: Option<u64>,
}

/// Location descriptor returned by trends/place.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendLocation {
    /// Human-readable location name.
    pub name: String,

    /// Twitter WOEID for the location.
    pub woeid: u64,
}

/// Trends payload for a location (Twitter v1.1 trends/place format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendsPlace {
    /// List of trending topics.
    #[serde(default)]
    pub trends: Vec<Trend>,

    /// Timestamp indicating when the trends snapshot was generated.
    #[serde(default)]
    pub as_of: Option<String>,

    /// Timestamp indicating when this object was created.
    #[serde(default)]
    pub created_at: Option<String>,

    /// Associated locations for this trends payload.
    #[serde(default)]
    pub locations: Vec<TrendLocation>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn twitter_response_with_data() {
        let json = json!({
            "data": {"id": "1", "text": "Hello"},
            "meta": {"result_count": 1}
        });
        let resp: TwitterResponse<Tweet> = serde_json::from_value(json).unwrap();
        let tweet = resp.data.unwrap();
        assert_eq!(tweet.id, "1");
        assert_eq!(resp.meta.unwrap().result_count, Some(1));
    }

    #[test]
    fn twitter_response_empty() {
        let json = json!({});
        let resp: TwitterResponse<Tweet> = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_none());
        assert!(resp.includes.is_none());
        assert!(resp.errors.is_none());
    }

    #[test]
    fn includes_default() {
        let inc = Includes::default();
        assert!(inc.users.is_empty());
        assert!(inc.tweets.is_empty());
        assert!(inc.media.is_empty());
        assert!(inc.places.is_empty());
        assert!(inc.polls.is_empty());
    }

    #[test]
    fn response_meta_serde() {
        let json = json!({
            "result_count": 10,
            "next_token": "abc",
            "newest_id": "100",
            "oldest_id": "91"
        });
        let meta: ResponseMeta = serde_json::from_value(json).unwrap();
        assert_eq!(meta.result_count, Some(10));
        assert_eq!(meta.next_token.as_deref(), Some("abc"));
    }

    #[test]
    fn twitter_api_error_type_rename() {
        let json = json!({
            "title": "Not Found",
            "detail": "Could not find tweet",
            "type": "https://api.twitter.com/2/problems/resource-not-found",
            "resource_type": "tweet",
            "resource_id": "123"
        });
        let err: TwitterApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.title.as_deref(), Some("Not Found"));
        assert!(err.error_type.is_some());
    }

    #[test]
    fn tweet_serde_full() {
        let json = json!({
            "id": "123",
            "text": "Hello world!",
            "author_id": "456",
            "created_at": "2026-03-03T00:00:00Z",
            "lang": "en",
            "source": "Twitter Web App",
            "public_metrics": {
                "retweet_count": 10,
                "reply_count": 5,
                "like_count": 100,
                "quote_count": 2,
                "bookmark_count": 3
            }
        });
        let tweet: Tweet = serde_json::from_value(json).unwrap();
        assert_eq!(tweet.id, "123");
        let metrics = tweet.public_metrics.unwrap();
        assert_eq!(metrics.like_count, 100);
        assert_eq!(metrics.bookmark_count, Some(3));
    }

    #[test]
    fn tweet_default() {
        let tweet = Tweet::default();
        assert!(tweet.id.is_empty());
        assert!(tweet.author_id.is_none());
        assert!(tweet.referenced_tweets.is_none());
    }

    #[test]
    fn referenced_tweet_type_rename() {
        let rt = ReferencedTweet {
            ref_type: "quoted".into(),
            id: "999".into(),
        };
        let json_str = serde_json::to_string(&rt).unwrap();
        assert!(json_str.contains("\"type\":\"quoted\""));
        let back: ReferencedTweet = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.ref_type, "quoted");
    }

    #[test]
    fn user_serde() {
        let json = json!({
            "id": "u1",
            "name": "Alice",
            "username": "alice",
            "verified": true,
            "public_metrics": {
                "followers_count": 1000,
                "following_count": 500,
                "tweet_count": 5000,
                "listed_count": 50
            }
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.username, "alice");
        let metrics = user.public_metrics.unwrap();
        assert_eq!(metrics.followers_count, 1000);
    }

    #[test]
    fn entities_serde() {
        let json = json!({
            "hashtags": [{"tag": "rust", "start": 0, "end": 5}],
            "mentions": [{"username": "alice", "start": 6, "end": 12}],
            "urls": [{"url": "https://t.co/abc", "start": 13, "end": 36, "expanded_url": "https://example.com"}]
        });
        let ent: Entities = serde_json::from_value(json).unwrap();
        assert_eq!(ent.hashtags.unwrap()[0].tag, "rust");
        assert_eq!(ent.mentions.unwrap()[0].username, "alice");
    }

    #[test]
    fn media_type_rename() {
        let m = Media {
            media_key: "mk1".into(),
            media_type: "photo".into(),
            url: Some("https://pbs.twimg.com/photo.jpg".into()),
            preview_image_url: None,
            width: Some(1920),
            height: Some(1080),
            duration_ms: None,
            alt_text: Some("A photo".into()),
            public_metrics: None,
        };
        let json_str = serde_json::to_string(&m).unwrap();
        assert!(json_str.contains("\"type\":\"photo\""));
        let back: Media = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.media_type, "photo");
    }

    #[test]
    fn place_geo_type_rename() {
        let geo = PlaceGeo {
            geo_type: "Feature".into(),
            bbox: vec![-122.5, 37.7, -122.3, 37.8],
        };
        let json_str = serde_json::to_string(&geo).unwrap();
        assert!(json_str.contains("\"type\":\"Feature\""));
    }

    #[test]
    fn poll_serde() {
        let json = json!({
            "id": "poll1",
            "options": [
                {"position": 1, "label": "Yes", "votes": 100},
                {"position": 2, "label": "No", "votes": 50}
            ],
            "voting_status": "closed",
            "duration_minutes": 1440
        });
        let poll: Poll = serde_json::from_value(json).unwrap();
        assert_eq!(poll.options.len(), 2);
        assert_eq!(poll.options[0].votes, 100);
    }

    #[test]
    fn create_tweet_request_skip_none() {
        let req = CreateTweetRequest {
            text: Some("Hello".into()),
            ..Default::default()
        };
        let json_str = serde_json::to_string(&req).unwrap();
        assert!(json_str.contains("\"text\":\"Hello\""));
        assert!(!json_str.contains("reply"));
        assert!(!json_str.contains("media"));
        assert!(!json_str.contains("poll"));
    }

    #[test]
    fn create_tweet_response_serde() {
        let json = json!({
            "data": {"id": "new1", "text": "Hello", "edit_history_tweet_ids": ["new1"]}
        });
        let resp: CreateTweetResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.id, "new1");
    }

    #[test]
    fn delete_tweet_response_serde() {
        let json = json!({"data": {"deleted": true}});
        let resp: DeleteTweetResponse = serde_json::from_value(json).unwrap();
        assert!(resp.data.deleted);
    }

    #[test]
    fn retweet_response_serde() {
        let json = json!({"data": {"retweeted": true}});
        let resp: RetweetResponse = serde_json::from_value(json).unwrap();
        assert!(resp.data.retweeted);
    }

    #[test]
    fn like_response_serde() {
        let json = json!({"data": {"liked": true}});
        let resp: LikeResponse = serde_json::from_value(json).unwrap();
        assert!(resp.data.liked);
    }

    #[test]
    fn dm_event_serde() {
        let json = json!({
            "id": "dm1",
            "event_type": "MessageCreate",
            "text": "Hey!",
            "sender_id": "u1",
            "dm_conversation_id": "conv1"
        });
        let dm: DmEvent = serde_json::from_value(json).unwrap();
        assert_eq!(dm.event_type, "MessageCreate");
        assert_eq!(dm.text.as_deref(), Some("Hey!"));
    }

    #[test]
    fn send_dm_response_serde() {
        let json = json!({
            "data": {"dm_conversation_id": "conv1", "dm_event_id": "evt1"}
        });
        let resp: SendDmResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.dm_conversation_id, "conv1");
    }

    #[test]
    fn create_dm_conversation_request_serde() {
        let req = CreateDmConversationRequest {
            conversation_type: "Group".into(),
            participant_ids: vec!["u1".into(), "u2".into()],
            message: SendDmRequest {
                text: "Hi group!".into(),
            },
        };
        let json_str = serde_json::to_string(&req).unwrap();
        assert!(json_str.contains("\"conversation_type\":\"Group\""));
        assert!(json_str.contains("Hi group!"));
    }

    #[test]
    fn trend_serde() {
        let json = json!({
            "name": "#Rust",
            "url": "https://twitter.com/search?q=%23Rust",
            "query": "%23Rust",
            "tweet_volume": 50000
        });
        let trend: Trend = serde_json::from_value(json).unwrap();
        assert_eq!(trend.name, "#Rust");
        assert_eq!(trend.tweet_volume, Some(50000));
    }

    #[test]
    fn trends_place_serde() {
        let json = json!({
            "trends": [{"name": "#Rust", "url": "u", "query": "q"}],
            "as_of": "2026-03-03T00:00:00Z",
            "locations": [{"name": "Worldwide", "woeid": 1}]
        });
        let tp: TrendsPlace = serde_json::from_value(json).unwrap();
        assert_eq!(tp.trends.len(), 1);
        assert_eq!(tp.locations[0].woeid, 1);
    }

    #[test]
    fn stream_rule_skip_none() {
        let rule = StreamRule {
            id: None,
            value: "rust lang".into(),
            tag: None,
        };
        let json_str = serde_json::to_string(&rule).unwrap();
        assert!(!json_str.contains("\"tag\""));
    }

    #[test]
    fn stream_rules_response_serde() {
        let json = json!({
            "data": [{"id": "r1", "value": "rust", "tag": "lang"}],
            "meta": {"sent": "2026-03-03T00:00:00Z", "summary": {"created": 1}}
        });
        let resp: StreamRulesResponse = serde_json::from_value(json).unwrap();
        let rules = resp.data.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].tag.as_deref(), Some("lang"));
        let summary = resp.meta.unwrap().summary.unwrap();
        assert_eq!(summary.created, Some(1));
    }

    #[test]
    fn stream_tweet_serde() {
        let json = json!({
            "data": {"id": "t1", "text": "streaming"},
            "matching_rules": [{"id": "r1", "tag": "test"}]
        });
        let st: StreamTweet = serde_json::from_value(json).unwrap();
        assert_eq!(st.data.id, "t1");
        let rules = st.matching_rules.unwrap();
        assert_eq!(rules[0].id, "r1");
    }

    #[test]
    fn annotation_type_rename() {
        let ann = Annotation {
            annotation_type: "Person".into(),
            normalized_text: "Alice".into(),
            probability: 0.95,
            start: 0,
            end: 5,
        };
        let json_str = serde_json::to_string(&ann).unwrap();
        assert!(json_str.contains("\"type\":\"Person\""));
        let back: Annotation = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.annotation_type, "Person");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attachments
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attachments_with_media_keys() {
        let json = json!({
            "media_keys": ["mk_1", "mk_2"]
        });
        let att: Attachments = serde_json::from_value(json).unwrap();
        let keys = att.media_keys.unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], "mk_1");
        assert!(att.poll_ids.is_none());
    }

    #[test]
    fn attachments_with_poll_ids() {
        let json = json!({
            "poll_ids": ["poll_1"]
        });
        let att: Attachments = serde_json::from_value(json).unwrap();
        assert!(att.media_keys.is_none());
        let polls = att.poll_ids.unwrap();
        assert_eq!(polls.len(), 1);
        assert_eq!(polls[0], "poll_1");
    }

    #[test]
    fn attachments_both_none() {
        let json = json!({});
        let att: Attachments = serde_json::from_value(json).unwrap();
        assert!(att.media_keys.is_none());
        assert!(att.poll_ids.is_none());
    }

    #[test]
    fn attachments_roundtrip() {
        let att = Attachments {
            media_keys: Some(vec!["mk_a".into(), "mk_b".into()]),
            poll_ids: Some(vec!["p_1".into()]),
        };
        let json_str = serde_json::to_string(&att).unwrap();
        let back: Attachments = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.media_keys.unwrap().len(), 2);
        assert_eq!(back.poll_ids.unwrap().len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TweetPublicMetrics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tweet_public_metrics_clone_debug() {
        let m = TweetPublicMetrics {
            retweet_count: 10,
            reply_count: 5,
            like_count: 100,
            quote_count: 2,
            bookmark_count: Some(3),
            impression_count: Some(50000),
        };
        let cloned = m.clone();
        assert_eq!(cloned.retweet_count, 10);
        assert_eq!(cloned.impression_count, Some(50000));
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("impression_count"));
    }

    #[test]
    fn tweet_public_metrics_impression_count_present() {
        let json = json!({
            "retweet_count": 0,
            "reply_count": 0,
            "like_count": 0,
            "quote_count": 0,
            "impression_count": 12345
        });
        let m: TweetPublicMetrics = serde_json::from_value(json).unwrap();
        assert_eq!(m.impression_count, Some(12345));
        assert_eq!(m.bookmark_count, None);
    }

    #[test]
    fn tweet_public_metrics_roundtrip() {
        let m = TweetPublicMetrics {
            retweet_count: 7,
            reply_count: 3,
            like_count: 42,
            quote_count: 1,
            bookmark_count: None,
            impression_count: None,
        };
        let json_str = serde_json::to_string(&m).unwrap();
        let back: TweetPublicMetrics = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.like_count, 42);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ContextAnnotation, ContextAnnotationDomain, ContextAnnotationEntity
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn context_annotation_roundtrip() {
        let ca = ContextAnnotation {
            domain: ContextAnnotationDomain {
                id: "46".into(),
                name: "Brand Category".into(),
                description: Some("A brand category".into()),
            },
            entity: ContextAnnotationEntity {
                id: "781974596752842752".into(),
                name: "Services".into(),
                description: None,
            },
        };
        let json_str = serde_json::to_string(&ca).unwrap();
        let back: ContextAnnotation = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.domain.id, "46");
        assert_eq!(back.entity.name, "Services");
    }

    #[test]
    fn context_annotation_domain_with_description() {
        let json = json!({
            "id": "10",
            "name": "Person",
            "description": "A public figure"
        });
        let d: ContextAnnotationDomain = serde_json::from_value(json).unwrap();
        assert_eq!(d.description.as_deref(), Some("A public figure"));
    }

    #[test]
    fn context_annotation_domain_without_description() {
        let json = json!({"id": "10", "name": "Person"});
        let d: ContextAnnotationDomain = serde_json::from_value(json).unwrap();
        assert!(d.description.is_none());
        assert_eq!(d.name, "Person");
    }

    #[test]
    fn context_annotation_entity_with_description() {
        let json = json!({
            "id": "999",
            "name": "Rust",
            "description": "The Rust programming language"
        });
        let e: ContextAnnotationEntity = serde_json::from_value(json).unwrap();
        assert_eq!(e.description.as_deref(), Some("The Rust programming language"));
    }

    #[test]
    fn context_annotation_entity_without_description() {
        let json = json!({"id": "999", "name": "Rust"});
        let e: ContextAnnotationEntity = serde_json::from_value(json).unwrap();
        assert!(e.description.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UserPublicMetrics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn user_public_metrics_clone() {
        let m = UserPublicMetrics {
            followers_count: 1000,
            following_count: 200,
            tweet_count: 5000,
            listed_count: 50,
            like_count: Some(12000),
        };
        let cloned = m.clone();
        assert_eq!(cloned.followers_count, 1000);
        assert_eq!(cloned.like_count, Some(12000));
    }

    #[test]
    fn user_public_metrics_with_like_count() {
        let json = json!({
            "followers_count": 500,
            "following_count": 100,
            "tweet_count": 3000,
            "listed_count": 25,
            "like_count": 8000
        });
        let m: UserPublicMetrics = serde_json::from_value(json).unwrap();
        assert_eq!(m.like_count, Some(8000));
    }

    #[test]
    fn user_public_metrics_without_like_count() {
        let json = json!({
            "followers_count": 500,
            "following_count": 100,
            "tweet_count": 3000,
            "listed_count": 25
        });
        let m: UserPublicMetrics = serde_json::from_value(json).unwrap();
        assert!(m.like_count.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UserEntities
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn user_entities_with_url_and_description() {
        let json = json!({
            "url": {
                "urls": [{"url": "https://t.co/abc", "expanded_url": "https://example.com", "start": 0, "end": 23}]
            },
            "description": {
                "urls": [{"url": "https://t.co/def", "start": 10, "end": 33}]
            }
        });
        let ue: UserEntities = serde_json::from_value(json).unwrap();
        assert_eq!(ue.url.as_ref().unwrap().urls.len(), 1);
        assert_eq!(ue.description.as_ref().unwrap().urls.len(), 1);
    }

    #[test]
    fn user_entities_empty() {
        let json = json!({});
        let ue: UserEntities = serde_json::from_value(json).unwrap();
        assert!(ue.url.is_none());
        assert!(ue.description.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EntityUrls
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn entity_urls_roundtrip() {
        let eu = EntityUrls {
            urls: vec![
                UrlEntity {
                    url: "https://t.co/a".into(),
                    expanded_url: Some("https://example.com".into()),
                    display_url: Some("example.com".into()),
                    unwound_url: None,
                    start: 0,
                    end: 23,
                    status: None,
                    title: None,
                    description: None,
                    media_key: None,
                },
            ],
        };
        let json_str = serde_json::to_string(&eu).unwrap();
        let back: EntityUrls = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.urls.len(), 1);
        assert_eq!(back.urls[0].url, "https://t.co/a");
    }

    #[test]
    fn entity_urls_empty_list() {
        let json = json!({"urls": []});
        let eu: EntityUrls = serde_json::from_value(json).unwrap();
        assert!(eu.urls.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hashtag
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn hashtag_roundtrip() {
        let h = Hashtag {
            tag: "rustlang".into(),
            start: 0,
            end: 9,
        };
        let json_str = serde_json::to_string(&h).unwrap();
        let back: Hashtag = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.tag, "rustlang");
        assert_eq!(back.start, 0);
        assert_eq!(back.end, 9);
    }

    #[test]
    fn hashtag_clone() {
        let h = Hashtag {
            tag: "test".into(),
            start: 5,
            end: 10,
        };
        let cloned = h.clone();
        assert_eq!(cloned.tag, "test");
        assert_eq!(cloned.start, 5);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Mention
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn mention_with_id() {
        let json = json!({
            "username": "alice",
            "start": 0,
            "end": 6,
            "id": "12345"
        });
        let m: Mention = serde_json::from_value(json).unwrap();
        assert_eq!(m.username, "alice");
        assert_eq!(m.id.as_deref(), Some("12345"));
    }

    #[test]
    fn mention_without_id() {
        let json = json!({
            "username": "bob",
            "start": 0,
            "end": 4
        });
        let m: Mention = serde_json::from_value(json).unwrap();
        assert_eq!(m.username, "bob");
        assert!(m.id.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UrlEntity
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn url_entity_full_fields() {
        let json = json!({
            "url": "https://t.co/xyz",
            "expanded_url": "https://example.com/article",
            "display_url": "example.com/article",
            "unwound_url": "https://example.com/article?final=true",
            "start": 10,
            "end": 33,
            "status": 200,
            "title": "An Article",
            "description": "A great article about Rust",
            "media_key": "mk_99"
        });
        let u: UrlEntity = serde_json::from_value(json).unwrap();
        assert_eq!(u.url, "https://t.co/xyz");
        assert_eq!(u.expanded_url.as_deref(), Some("https://example.com/article"));
        assert_eq!(u.display_url.as_deref(), Some("example.com/article"));
        assert_eq!(u.unwound_url.as_deref(), Some("https://example.com/article?final=true"));
        assert_eq!(u.status, Some(200));
        assert_eq!(u.title.as_deref(), Some("An Article"));
        assert_eq!(u.description.as_deref(), Some("A great article about Rust"));
        assert_eq!(u.media_key.as_deref(), Some("mk_99"));
    }

    #[test]
    fn url_entity_minimal() {
        let json = json!({
            "url": "https://t.co/abc",
            "start": 0,
            "end": 23
        });
        let u: UrlEntity = serde_json::from_value(json).unwrap();
        assert_eq!(u.url, "https://t.co/abc");
        assert!(u.expanded_url.is_none());
        assert!(u.display_url.is_none());
        assert!(u.unwound_url.is_none());
        assert!(u.status.is_none());
        assert!(u.title.is_none());
        assert!(u.description.is_none());
        assert!(u.media_key.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cashtag
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cashtag_roundtrip() {
        let c = Cashtag {
            tag: "AAPL".into(),
            start: 5,
            end: 10,
        };
        let json_str = serde_json::to_string(&c).unwrap();
        let back: Cashtag = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.tag, "AAPL");
        assert_eq!(back.start, 5);
        assert_eq!(back.end, 10);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MediaPublicMetrics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn media_public_metrics_roundtrip() {
        let m = MediaPublicMetrics { view_count: 99999 };
        let json_str = serde_json::to_string(&m).unwrap();
        let back: MediaPublicMetrics = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.view_count, 99999);
    }

    #[test]
    fn media_public_metrics_from_json() {
        let json = json!({"view_count": 0});
        let m: MediaPublicMetrics = serde_json::from_value(json).unwrap();
        assert_eq!(m.view_count, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Place
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn place_full_fields() {
        let json = json!({
            "id": "place_1",
            "full_name": "San Francisco, CA",
            "name": "San Francisco",
            "country": "United States",
            "country_code": "US",
            "place_type": "city",
            "geo": {
                "type": "Feature",
                "bbox": [-122.5, 37.7, -122.3, 37.8]
            }
        });
        let p: Place = serde_json::from_value(json).unwrap();
        assert_eq!(p.id, "place_1");
        assert_eq!(p.full_name, "San Francisco, CA");
        assert_eq!(p.name.as_deref(), Some("San Francisco"));
        assert_eq!(p.country.as_deref(), Some("United States"));
        assert_eq!(p.country_code.as_deref(), Some("US"));
        assert_eq!(p.place_type.as_deref(), Some("city"));
        let geo = p.geo.unwrap();
        assert_eq!(geo.geo_type, "Feature");
        assert_eq!(geo.bbox.len(), 4);
    }

    #[test]
    fn place_minimal() {
        let json = json!({
            "id": "place_2",
            "full_name": "Somewhere"
        });
        let p: Place = serde_json::from_value(json).unwrap();
        assert_eq!(p.full_name, "Somewhere");
        assert!(p.name.is_none());
        assert!(p.country.is_none());
        assert!(p.geo.is_none());
    }

    #[test]
    fn place_clone() {
        let p = Place {
            id: "p1".into(),
            full_name: "NYC, NY".into(),
            name: Some("NYC".into()),
            country: None,
            country_code: None,
            place_type: None,
            geo: None,
        };
        let cloned = p.clone();
        assert_eq!(cloned.id, "p1");
        assert_eq!(cloned.name.as_deref(), Some("NYC"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PollOption
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn poll_option_roundtrip() {
        let po = PollOption {
            position: 1,
            label: "Yes".into(),
            votes: 42,
        };
        let json_str = serde_json::to_string(&po).unwrap();
        let back: PollOption = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.position, 1);
        assert_eq!(back.label, "Yes");
        assert_eq!(back.votes, 42);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TweetReply
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tweet_reply_with_exclude_ids() {
        let tr = TweetReply {
            in_reply_to_tweet_id: "tweet_1".into(),
            exclude_reply_user_ids: Some(vec!["u1".into(), "u2".into()]),
        };
        let json_str = serde_json::to_string(&tr).unwrap();
        assert!(json_str.contains("\"exclude_reply_user_ids\""));
        let back: TweetReply = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.exclude_reply_user_ids.unwrap().len(), 2);
    }

    #[test]
    fn tweet_reply_without_exclude_ids() {
        let tr = TweetReply {
            in_reply_to_tweet_id: "tweet_2".into(),
            exclude_reply_user_ids: None,
        };
        let json_str = serde_json::to_string(&tr).unwrap();
        assert!(!json_str.contains("exclude_reply_user_ids"));
        assert!(json_str.contains("tweet_2"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TweetMedia
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tweet_media_with_tagged_user_ids() {
        let tm = TweetMedia {
            media_ids: vec!["m1".into(), "m2".into()],
            tagged_user_ids: Some(vec!["u1".into()]),
        };
        let json_str = serde_json::to_string(&tm).unwrap();
        assert!(json_str.contains("tagged_user_ids"));
        let back: TweetMedia = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.media_ids.len(), 2);
        assert_eq!(back.tagged_user_ids.unwrap().len(), 1);
    }

    #[test]
    fn tweet_media_without_tagged_user_ids() {
        let tm = TweetMedia {
            media_ids: vec!["m1".into()],
            tagged_user_ids: None,
        };
        let json_str = serde_json::to_string(&tm).unwrap();
        assert!(!json_str.contains("tagged_user_ids"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TweetPoll
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tweet_poll_roundtrip() {
        let tp = TweetPoll {
            options: vec!["Yes".into(), "No".into(), "Maybe".into()],
            duration_minutes: 1440,
        };
        let json_str = serde_json::to_string(&tp).unwrap();
        let back: TweetPoll = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.options.len(), 3);
        assert_eq!(back.duration_minutes, 1440);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TweetGeo
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tweet_geo_roundtrip() {
        let tg = TweetGeo {
            place_id: "abc123".into(),
        };
        let json_str = serde_json::to_string(&tg).unwrap();
        let back: TweetGeo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.place_id, "abc123");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CreatedTweet
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn created_tweet_with_edit_history() {
        let json = json!({
            "id": "new_1",
            "text": "Hello",
            "edit_history_tweet_ids": ["new_1", "new_1_edit"]
        });
        let ct: CreatedTweet = serde_json::from_value(json).unwrap();
        let ids = ct.edit_history_tweet_ids.unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[1], "new_1_edit");
    }

    #[test]
    fn created_tweet_without_edit_history() {
        let json = json!({"id": "new_2", "text": "World"});
        let ct: CreatedTweet = serde_json::from_value(json).unwrap();
        assert!(ct.edit_history_tweet_ids.is_none());
        assert_eq!(ct.text, "World");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DeletedTweet
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn deleted_tweet_false() {
        let json = json!({"deleted": false});
        let dt: DeletedTweet = serde_json::from_value(json).unwrap();
        assert!(!dt.deleted);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RetweetData
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retweet_data_retweeted_false() {
        let json = json!({"retweeted": false});
        let rd: RetweetData = serde_json::from_value(json).unwrap();
        assert!(!rd.retweeted);
    }

    #[test]
    fn retweet_data_roundtrip() {
        let rd = RetweetData { retweeted: true };
        let json_str = serde_json::to_string(&rd).unwrap();
        let back: RetweetData = serde_json::from_str(&json_str).unwrap();
        assert!(back.retweeted);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LikeData
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn like_data_liked_false() {
        let json = json!({"liked": false});
        let ld: LikeData = serde_json::from_value(json).unwrap();
        assert!(!ld.liked);
    }

    #[test]
    fn like_data_roundtrip() {
        let ld = LikeData { liked: true };
        let json_str = serde_json::to_string(&ld).unwrap();
        let back: LikeData = serde_json::from_str(&json_str).unwrap();
        assert!(back.liked);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UnretweetResponse
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn unretweet_response_roundtrip() {
        let json = json!({"data": {"retweeted": false}});
        let resp: UnretweetResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.data.retweeted);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UnlikeResponse
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn unlike_response_roundtrip() {
        let json = json!({"data": {"liked": false}});
        let resp: UnlikeResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.data.liked);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SendDmRequest
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn send_dm_request_roundtrip() {
        let req = SendDmRequest {
            text: "Hello, DM!".into(),
        };
        let json_str = serde_json::to_string(&req).unwrap();
        let back: SendDmRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.text, "Hello, DM!");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SentDmData
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sent_dm_data_roundtrip() {
        let d = SentDmData {
            dm_conversation_id: "conv_123".into(),
            dm_event_id: "evt_456".into(),
        };
        let json_str = serde_json::to_string(&d).unwrap();
        let back: SentDmData = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.dm_conversation_id, "conv_123");
        assert_eq!(back.dm_event_id, "evt_456");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TrendLocation
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trend_location_roundtrip() {
        let tl = TrendLocation {
            name: "San Francisco".into(),
            woeid: 2487956,
        };
        let json_str = serde_json::to_string(&tl).unwrap();
        let back: TrendLocation = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "San Francisco");
        assert_eq!(back.woeid, 2487956);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StreamRulesMeta
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn stream_rules_meta_without_summary() {
        let json = json!({"sent": "2026-03-05T00:00:00Z"});
        let m: StreamRulesMeta = serde_json::from_value(json).unwrap();
        assert_eq!(m.sent, "2026-03-05T00:00:00Z");
        assert!(m.summary.is_none());
    }

    #[test]
    fn stream_rules_meta_with_summary() {
        let json = json!({
            "sent": "2026-03-05T00:00:00Z",
            "summary": {"created": 2, "not_created": 0, "valid": 2}
        });
        let m: StreamRulesMeta = serde_json::from_value(json).unwrap();
        let s = m.summary.unwrap();
        assert_eq!(s.created, Some(2));
        assert_eq!(s.not_created, Some(0));
        assert_eq!(s.valid, Some(2));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RulesSummary
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rules_summary_all_fields() {
        let json = json!({
            "created": 3,
            "not_created": 1,
            "deleted": 2,
            "not_deleted": 0,
            "valid": 5,
            "invalid": 1
        });
        let rs: RulesSummary = serde_json::from_value(json).unwrap();
        assert_eq!(rs.created, Some(3));
        assert_eq!(rs.not_created, Some(1));
        assert_eq!(rs.deleted, Some(2));
        assert_eq!(rs.not_deleted, Some(0));
        assert_eq!(rs.valid, Some(5));
        assert_eq!(rs.invalid, Some(1));
    }

    #[test]
    fn rules_summary_all_none() {
        let json = json!({});
        let rs: RulesSummary = serde_json::from_value(json).unwrap();
        assert!(rs.created.is_none());
        assert!(rs.not_created.is_none());
        assert!(rs.deleted.is_none());
        assert!(rs.not_deleted.is_none());
        assert!(rs.valid.is_none());
        assert!(rs.invalid.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MatchingRule
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn matching_rule_with_tag() {
        let json = json!({"id": "r1", "tag": "sports"});
        let mr: MatchingRule = serde_json::from_value(json).unwrap();
        assert_eq!(mr.id, "r1");
        assert_eq!(mr.tag.as_deref(), Some("sports"));
    }

    #[test]
    fn matching_rule_without_tag() {
        let json = json!({"id": "r2"});
        let mr: MatchingRule = serde_json::from_value(json).unwrap();
        assert_eq!(mr.id, "r2");
        assert!(mr.tag.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SearchTweetsParams
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn search_tweets_params_default() {
        let p = SearchTweetsParams::default();
        assert!(p.query.is_empty());
        assert!(p.max_results.is_none());
        assert!(p.next_token.is_none());
        assert!(p.since_id.is_none());
        assert!(p.until_id.is_none());
        assert!(p.start_time.is_none());
        assert!(p.end_time.is_none());
        assert!(p.sort_order.is_none());
        assert!(p.tweet_fields.is_none());
        assert!(p.user_fields.is_none());
        assert!(p.media_fields.is_none());
        assert!(p.expansions.is_none());
    }

    #[test]
    fn search_tweets_params_with_query() {
        let p = SearchTweetsParams {
            query: "rust lang".into(),
            max_results: Some(50),
            sort_order: Some("recency".into()),
            tweet_fields: Some(vec!["author_id".into(), "created_at".into()]),
            ..Default::default()
        };
        assert_eq!(p.query, "rust lang");
        assert_eq!(p.max_results, Some(50));
        assert_eq!(p.sort_order.as_deref(), Some("recency"));
        assert_eq!(p.tweet_fields.as_ref().unwrap().len(), 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AddStreamRulesRequest
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn add_stream_rules_request_roundtrip() {
        let req = AddStreamRulesRequest {
            add: vec![
                StreamRule {
                    id: None,
                    value: "rust -is:retweet".into(),
                    tag: Some("rust_filter".into()),
                },
                StreamRule {
                    id: None,
                    value: "python".into(),
                    tag: None,
                },
            ],
        };
        let json_str = serde_json::to_string(&req).unwrap();
        let back: AddStreamRulesRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.add.len(), 2);
        assert_eq!(back.add[0].value, "rust -is:retweet");
        assert_eq!(back.add[0].tag.as_deref(), Some("rust_filter"));
        assert!(back.add[1].tag.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DeleteStreamRulesRequest
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn delete_stream_rules_request_roundtrip() {
        let req = DeleteStreamRulesRequest {
            delete: DeleteRulesSpec {
                ids: vec!["r1".into(), "r2".into(), "r3".into()],
            },
        };
        let json_str = serde_json::to_string(&req).unwrap();
        let back: DeleteStreamRulesRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.delete.ids.len(), 3);
        assert_eq!(back.delete.ids[2], "r3");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DeleteRulesSpec
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn delete_rules_spec_roundtrip() {
        let spec = DeleteRulesSpec {
            ids: vec!["id_a".into(), "id_b".into()],
        };
        let json_str = serde_json::to_string(&spec).unwrap();
        let back: DeleteRulesSpec = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.ids, vec!["id_a", "id_b"]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Enhanced coverage for already-tested types
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn twitter_response_with_includes_populated() {
        let json = json!({
            "data": [
                {"id": "t1", "text": "Hello"},
                {"id": "t2", "text": "World"}
            ],
            "includes": {
                "users": [{"id": "u1", "name": "Alice", "username": "alice"}],
                "tweets": [{"id": "t0", "text": "Original"}],
                "media": [{"media_key": "mk_1", "type": "photo"}],
                "places": [{"id": "p1", "full_name": "NYC, NY"}],
                "polls": [{"id": "poll1", "options": [{"position": 1, "label": "A", "votes": 10}]}]
            },
            "meta": {"result_count": 2}
        });
        let resp: TwitterResponse<Vec<Tweet>> = serde_json::from_value(json).unwrap();
        let tweets = resp.data.unwrap();
        assert_eq!(tweets.len(), 2);
        let inc = resp.includes.unwrap();
        assert_eq!(inc.users.len(), 1);
        assert_eq!(inc.users[0].username, "alice");
        assert_eq!(inc.tweets.len(), 1);
        assert_eq!(inc.media.len(), 1);
        assert_eq!(inc.places.len(), 1);
        assert_eq!(inc.polls.len(), 1);
    }

    #[test]
    fn twitter_response_with_errors() {
        let json = json!({
            "errors": [
                {
                    "title": "Not Found Error",
                    "detail": "Could not find tweet with id: [999]",
                    "type": "https://api.twitter.com/2/problems/resource-not-found",
                    "resource_type": "tweet",
                    "resource_id": "999",
                    "parameter": "id",
                    "field": "data.id",
                    "section": "data"
                }
            ]
        });
        let resp: TwitterResponse<Tweet> = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_none());
        let errors = resp.errors.unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].title.as_deref(), Some("Not Found Error"));
        assert_eq!(errors[0].parameter.as_deref(), Some("id"));
        assert_eq!(errors[0].field.as_deref(), Some("data.id"));
        assert_eq!(errors[0].section.as_deref(), Some("data"));
    }

    #[test]
    fn tweet_clone_debug() {
        let tweet = Tweet {
            id: "123".into(),
            text: "Hello world".into(),
            author_id: Some("456".into()),
            ..Default::default()
        };
        let cloned = tweet.clone();
        assert_eq!(cloned.id, "123");
        assert_eq!(cloned.author_id.as_deref(), Some("456"));
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("Hello world"));
    }

    #[test]
    fn tweet_with_referenced_tweets() {
        let json = json!({
            "id": "t1",
            "text": "RT @alice: Hello",
            "referenced_tweets": [
                {"type": "retweeted", "id": "t0"},
                {"type": "quoted", "id": "t_q"}
            ]
        });
        let tweet: Tweet = serde_json::from_value(json).unwrap();
        let refs = tweet.referenced_tweets.unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].ref_type, "retweeted");
        assert_eq!(refs[1].ref_type, "quoted");
    }

    #[test]
    fn tweet_with_attachments() {
        let json = json!({
            "id": "t1",
            "text": "Photo tweet",
            "attachments": {
                "media_keys": ["mk_1", "mk_2"]
            }
        });
        let tweet: Tweet = serde_json::from_value(json).unwrap();
        let att = tweet.attachments.unwrap();
        assert_eq!(att.media_keys.unwrap().len(), 2);
    }

    #[test]
    fn tweet_with_entities() {
        let json = json!({
            "id": "t1",
            "text": "#rust @alice https://t.co/abc $AAPL",
            "entities": {
                "hashtags": [{"tag": "rust", "start": 0, "end": 5}],
                "mentions": [{"username": "alice", "start": 6, "end": 12, "id": "u1"}],
                "urls": [{"url": "https://t.co/abc", "start": 13, "end": 33}],
                "cashtags": [{"tag": "AAPL", "start": 34, "end": 39}],
                "annotations": [{"type": "Organization", "normalized_text": "Apple", "probability": 0.9, "start": 34, "end": 39}]
            }
        });
        let tweet: Tweet = serde_json::from_value(json).unwrap();
        let ent = tweet.entities.unwrap();
        assert_eq!(ent.hashtags.unwrap().len(), 1);
        assert_eq!(ent.mentions.as_ref().unwrap()[0].id.as_deref(), Some("u1"));
        assert_eq!(ent.urls.unwrap().len(), 1);
        assert_eq!(ent.cashtags.unwrap()[0].tag, "AAPL");
        assert_eq!(ent.annotations.unwrap()[0].annotation_type, "Organization");
    }

    #[test]
    fn tweet_with_context_annotations() {
        let json = json!({
            "id": "t1",
            "text": "Talking about tech",
            "context_annotations": [
                {
                    "domain": {"id": "46", "name": "Brand Category"},
                    "entity": {"id": "781974596752842752", "name": "Services"}
                },
                {
                    "domain": {"id": "65", "name": "Interests and Hobbies Category", "description": "General interest"},
                    "entity": {"id": "848920371311001600", "name": "Technology", "description": "Tech interest"}
                }
            ]
        });
        let tweet: Tweet = serde_json::from_value(json).unwrap();
        let cas = tweet.context_annotations.unwrap();
        assert_eq!(cas.len(), 2);
        assert_eq!(cas[0].domain.name, "Brand Category");
        assert!(cas[0].domain.description.is_none());
        assert_eq!(cas[1].entity.description.as_deref(), Some("Tech interest"));
    }

    #[test]
    fn user_clone_debug() {
        let user = User {
            id: "u1".into(),
            name: "Alice".into(),
            username: "alice".into(),
            description: Some("Rustacean".into()),
            ..Default::default()
        };
        let cloned = user.clone();
        assert_eq!(cloned.username, "alice");
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("Rustacean"));
    }

    #[test]
    fn user_with_all_optional_fields() {
        let json = json!({
            "id": "u1",
            "name": "Alice",
            "username": "alice",
            "description": "Developer",
            "profile_image_url": "https://pbs.twimg.com/profile/alice.jpg",
            "location": "San Francisco, CA",
            "url": "https://alice.dev",
            "verified": true,
            "verified_type": "blue",
            "protected": false,
            "created_at": "2020-01-01T00:00:00Z",
            "public_metrics": {
                "followers_count": 10000,
                "following_count": 500,
                "tweet_count": 25000,
                "listed_count": 200,
                "like_count": 50000
            },
            "pinned_tweet_id": "pin_1",
            "entities": {
                "url": {"urls": [{"url": "https://t.co/xyz", "expanded_url": "https://alice.dev", "start": 0, "end": 23}]},
                "description": {"urls": []}
            }
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.description.as_deref(), Some("Developer"));
        assert_eq!(user.profile_image_url.as_deref(), Some("https://pbs.twimg.com/profile/alice.jpg"));
        assert_eq!(user.location.as_deref(), Some("San Francisco, CA"));
        assert_eq!(user.url.as_deref(), Some("https://alice.dev"));
        assert_eq!(user.verified, Some(true));
        assert_eq!(user.verified_type.as_deref(), Some("blue"));
        assert_eq!(user.protected, Some(false));
        assert_eq!(user.created_at.as_deref(), Some("2020-01-01T00:00:00Z"));
        assert_eq!(user.pinned_tweet_id.as_deref(), Some("pin_1"));
        let metrics = user.public_metrics.unwrap();
        assert_eq!(metrics.like_count, Some(50000));
        let ent = user.entities.unwrap();
        assert_eq!(ent.url.unwrap().urls.len(), 1);
        assert!(ent.description.unwrap().urls.is_empty());
    }

    #[test]
    fn includes_with_all_expansion_types() {
        let json = json!({
            "users": [
                {"id": "u1", "name": "Alice", "username": "alice"},
                {"id": "u2", "name": "Bob", "username": "bob"}
            ],
            "tweets": [
                {"id": "t1", "text": "Original tweet"}
            ],
            "media": [
                {"media_key": "mk1", "type": "photo", "url": "https://img.com/1.jpg"},
                {"media_key": "mk2", "type": "video", "duration_ms": 30000}
            ],
            "places": [
                {"id": "p1", "full_name": "London, UK"}
            ],
            "polls": [
                {"id": "poll1", "options": [{"position": 1, "label": "Yes", "votes": 100}], "voting_status": "open"},
                {"id": "poll2", "options": [{"position": 1, "label": "A", "votes": 50}, {"position": 2, "label": "B", "votes": 60}]}
            ]
        });
        let inc: Includes = serde_json::from_value(json).unwrap();
        assert_eq!(inc.users.len(), 2);
        assert_eq!(inc.tweets.len(), 1);
        assert_eq!(inc.media.len(), 2);
        assert_eq!(inc.media[1].media_type, "video");
        assert_eq!(inc.media[1].duration_ms, Some(30000));
        assert_eq!(inc.places.len(), 1);
        assert_eq!(inc.polls.len(), 2);
        assert_eq!(inc.polls[0].voting_status.as_deref(), Some("open"));
    }

    #[test]
    fn stream_rule_with_id_and_tag() {
        let rule = StreamRule {
            id: Some("rule_123".into()),
            value: "from:twitterdev".into(),
            tag: Some("dev_tweets".into()),
        };
        let json_str = serde_json::to_string(&rule).unwrap();
        assert!(json_str.contains("\"id\":\"rule_123\""));
        assert!(json_str.contains("\"tag\":\"dev_tweets\""));
        let back: StreamRule = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id.as_deref(), Some("rule_123"));
        assert_eq!(back.tag.as_deref(), Some("dev_tweets"));
        assert_eq!(back.value, "from:twitterdev");
    }
}
