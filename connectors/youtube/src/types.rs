//! YouTube Data API v3 types.

use serde::{Deserialize, Serialize};

// ── Common ──────────────────────────────────────────────────────

/// Thumbnail information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thumbnail {
    pub url: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// Set of thumbnails at different resolutions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThumbnailSet {
    pub default: Option<Thumbnail>,
    pub medium: Option<Thumbnail>,
    pub high: Option<Thumbnail>,
    pub standard: Option<Thumbnail>,
    pub maxres: Option<Thumbnail>,
}

/// Page info for paginated responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    pub total_results: u32,
    pub results_per_page: u32,
}

// ── Search ──────────────────────────────────────────────────────

/// A search result item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub kind: String,
    pub etag: String,
    pub id: SearchResultId,
    pub snippet: Option<SearchSnippet>,
}

/// The ID portion of a search result (can be video, channel, or playlist).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResultId {
    pub kind: String,
    pub video_id: Option<String>,
    pub channel_id: Option<String>,
    pub playlist_id: Option<String>,
}

/// Snippet data from a search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchSnippet {
    pub published_at: Option<String>,
    pub channel_id: Option<String>,
    pub title: String,
    pub description: String,
    pub thumbnails: Option<ThumbnailSet>,
    pub channel_title: Option<String>,
    pub live_broadcast_content: Option<String>,
}

/// Search list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchListResponse {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub prev_page_token: Option<String>,
    pub page_info: Option<PageInfo>,
    pub items: Vec<SearchResult>,
}

// ── Video ───────────────────────────────────────────────────────

/// Video resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Video {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<VideoSnippet>,
    pub content_details: Option<ContentDetails>,
    pub statistics: Option<VideoStatistics>,
}

/// Video snippet data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoSnippet {
    pub published_at: Option<String>,
    pub channel_id: Option<String>,
    pub title: String,
    pub description: String,
    pub thumbnails: Option<ThumbnailSet>,
    pub channel_title: Option<String>,
    pub tags: Option<Vec<String>>,
    pub category_id: Option<String>,
    pub live_broadcast_content: Option<String>,
    pub default_language: Option<String>,
    pub default_audio_language: Option<String>,
}

/// Video content details (duration, definition, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentDetails {
    pub duration: Option<String>,
    pub dimension: Option<String>,
    pub definition: Option<String>,
    pub caption: Option<String>,
    pub licensed_content: Option<bool>,
    pub projection: Option<String>,
}

/// Video statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoStatistics {
    pub view_count: Option<String>,
    pub like_count: Option<String>,
    pub dislike_count: Option<String>,
    pub favorite_count: Option<String>,
    pub comment_count: Option<String>,
}

/// Video list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoListResponse {
    pub kind: String,
    pub etag: String,
    pub page_info: Option<PageInfo>,
    pub items: Vec<Video>,
}

// ── Channel ─────────────────────────────────────────────────────

/// Channel resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<ChannelSnippet>,
    pub statistics: Option<ChannelStatistics>,
    pub content_details: Option<ChannelContentDetails>,
}

/// Channel snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelSnippet {
    pub title: String,
    pub description: String,
    pub custom_url: Option<String>,
    pub published_at: Option<String>,
    pub thumbnails: Option<ThumbnailSet>,
    pub country: Option<String>,
}

/// Channel statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStatistics {
    pub view_count: Option<String>,
    pub subscriber_count: Option<String>,
    pub hidden_subscriber_count: Option<bool>,
    pub video_count: Option<String>,
}

/// Channel content details (related playlists).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelContentDetails {
    pub related_playlists: Option<RelatedPlaylists>,
}

/// Related playlists for a channel (uploads, likes, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedPlaylists {
    pub likes: Option<String>,
    pub uploads: Option<String>,
}

/// Channel list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelListResponse {
    pub kind: String,
    pub etag: String,
    pub page_info: Option<PageInfo>,
    pub items: Vec<Channel>,
}

// ── Playlist Items ──────────────────────────────────────────────

/// Playlist item resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistItem {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<PlaylistItemSnippet>,
    pub content_details: Option<PlaylistItemContentDetails>,
}

/// Playlist item snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistItemSnippet {
    pub published_at: Option<String>,
    pub channel_id: Option<String>,
    pub title: String,
    pub description: String,
    pub thumbnails: Option<ThumbnailSet>,
    pub channel_title: Option<String>,
    pub playlist_id: Option<String>,
    pub position: Option<u32>,
    pub resource_id: Option<ResourceId>,
}

/// Resource ID for a playlist item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceId {
    pub kind: String,
    pub video_id: Option<String>,
}

/// Playlist item content details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistItemContentDetails {
    pub video_id: Option<String>,
    pub video_published_at: Option<String>,
}

/// Playlist items list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistItemListResponse {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub prev_page_token: Option<String>,
    pub page_info: Option<PageInfo>,
    pub items: Vec<PlaylistItem>,
}

// ── Comments ────────────────────────────────────────────────────

/// Comment thread (top-level comment + replies).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentThread {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<CommentThreadSnippet>,
}

/// Comment thread snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentThreadSnippet {
    pub channel_id: Option<String>,
    pub video_id: Option<String>,
    pub top_level_comment: Option<Comment>,
    pub can_reply: Option<bool>,
    pub total_reply_count: Option<u32>,
    pub is_public: Option<bool>,
}

/// A single comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Comment {
    pub kind: Option<String>,
    pub etag: Option<String>,
    pub id: String,
    pub snippet: Option<CommentSnippet>,
}

/// Comment snippet data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentSnippet {
    pub author_display_name: Option<String>,
    pub author_profile_image_url: Option<String>,
    pub author_channel_url: Option<String>,
    pub text_display: Option<String>,
    pub text_original: Option<String>,
    pub parent_id: Option<String>,
    pub video_id: Option<String>,
    pub viewer_rating: Option<String>,
    pub like_count: Option<u32>,
    pub published_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Comment thread list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentThreadListResponse {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub page_info: Option<PageInfo>,
    pub items: Vec<CommentThread>,
}

// ── Captions ────────────────────────────────────────────────────

/// Caption track resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptionTrack {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<CaptionSnippet>,
}

/// Caption snippet data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptionSnippet {
    pub video_id: Option<String>,
    pub last_updated: Option<String>,
    pub track_kind: Option<String>,
    pub language: Option<String>,
    pub name: Option<String>,
    pub audio_track_type: Option<String>,
    pub is_cc: Option<bool>,
    pub is_draft: Option<bool>,
    pub is_auto_synced: Option<bool>,
    pub status: Option<String>,
}

/// Caption list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptionListResponse {
    pub kind: String,
    pub etag: String,
    pub items: Vec<CaptionTrack>,
}

// ── API Error ───────────────────────────────────────────────────

/// YouTube API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiError>,
}

/// YouTube API error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: Option<u16>,
    pub message: Option<String>,
    pub errors: Option<Vec<ApiErrorDetail>>,
}

/// Individual error detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    pub message: Option<String>,
    pub domain: Option<String>,
    pub reason: Option<String>,
}
