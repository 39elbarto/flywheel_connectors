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

// ── Playlists ───────────────────────────────────────────────────

/// Playlist resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Playlist {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<PlaylistSnippet>,
    pub content_details: Option<PlaylistContentDetails>,
}

/// Playlist snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistSnippet {
    pub published_at: Option<String>,
    pub channel_id: Option<String>,
    pub title: String,
    pub description: String,
    pub thumbnails: Option<ThumbnailSet>,
    pub channel_title: Option<String>,
}

/// Playlist content details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistContentDetails {
    pub item_count: Option<u32>,
}

/// Playlist list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistListResponse {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub prev_page_token: Option<String>,
    pub page_info: Option<PageInfo>,
    pub items: Vec<Playlist>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- PageInfo (camelCase) ----

    #[test]
    fn page_info_camel_case_serde() {
        let json = json!({"totalResults": 100, "resultsPerPage": 25});
        let pi: PageInfo = serde_json::from_value(json).unwrap();
        assert_eq!(pi.total_results, 100);
        assert_eq!(pi.results_per_page, 25);

        let out = serde_json::to_value(&pi).unwrap();
        assert_eq!(out["totalResults"], 100);
    }

    // ---- SearchResult ----

    #[test]
    fn search_result_serde() {
        let json = json!({
            "kind": "youtube#searchResult",
            "etag": "abc",
            "id": {
                "kind": "youtube#video",
                "videoId": "dQw4w9WgXcQ"
            },
            "snippet": {
                "title": "Rick Astley",
                "description": "Never gonna give you up",
                "publishedAt": "2009-10-25T06:57:33Z",
                "channelId": "UCuAXFkgsw1L7xaCfnd5JJOw",
                "channelTitle": "Rick Astley",
                "thumbnails": {
                    "default": {"url": "https://i.ytimg.com/vi/dQw4w9WgXcQ/default.jpg", "width": 120, "height": 90}
                }
            }
        });
        let sr: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(sr.kind, "youtube#searchResult");
        assert_eq!(sr.id.video_id, Some("dQw4w9WgXcQ".into()));
        assert!(sr.id.channel_id.is_none());
        let snippet = sr.snippet.unwrap();
        assert_eq!(snippet.title, "Rick Astley");
    }

    #[test]
    fn search_list_response_serde() {
        let json = json!({
            "kind": "youtube#searchListResponse",
            "etag": "xyz",
            "nextPageToken": "CAUQAA",
            "pageInfo": {"totalResults": 50, "resultsPerPage": 5},
            "items": []
        });
        let resp: SearchListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.next_page_token, Some("CAUQAA".into()));
        assert!(resp.items.is_empty());
    }

    // ---- Video ----

    #[test]
    fn video_serde_roundtrip() {
        let json = json!({
            "kind": "youtube#video",
            "etag": "abc",
            "id": "dQw4w9WgXcQ",
            "snippet": {
                "title": "Never Gonna Give You Up",
                "description": "The official video",
                "tags": ["music", "rick astley"],
                "categoryId": "10"
            },
            "contentDetails": {
                "duration": "PT3M33S",
                "dimension": "2d",
                "definition": "hd",
                "caption": "true",
                "licensedContent": true
            },
            "statistics": {
                "viewCount": "1500000000",
                "likeCount": "15000000",
                "commentCount": "3000000"
            }
        });
        let video: Video = serde_json::from_value(json).unwrap();
        assert_eq!(video.id, "dQw4w9WgXcQ");
        let snippet = video.snippet.unwrap();
        assert_eq!(snippet.tags.as_ref().unwrap().len(), 2);
        let cd = video.content_details.unwrap();
        assert_eq!(cd.duration, Some("PT3M33S".into()));
        let stats = video.statistics.unwrap();
        assert_eq!(stats.view_count, Some("1500000000".into()));
    }

    #[test]
    fn video_minimal_fields() {
        let json = json!({
            "kind": "youtube#video",
            "etag": "min",
            "id": "abc123"
        });
        let video: Video = serde_json::from_value(json).unwrap();
        assert!(video.snippet.is_none());
        assert!(video.content_details.is_none());
        assert!(video.statistics.is_none());
    }

    // ---- Channel ----

    #[test]
    fn channel_serde() {
        let json = json!({
            "kind": "youtube#channel",
            "etag": "ch_etag",
            "id": "UCuAXFkgsw1L7xaCfnd5JJOw",
            "snippet": {
                "title": "Rick Astley",
                "description": "Official channel",
                "customUrl": "@rickastley",
                "country": "GB"
            },
            "statistics": {
                "viewCount": "2000000000",
                "subscriberCount": "14000000",
                "hiddenSubscriberCount": false,
                "videoCount": "120"
            },
            "contentDetails": {
                "relatedPlaylists": {
                    "likes": "LL",
                    "uploads": "UUuAXFkgsw1L7xaCfnd5JJOw"
                }
            }
        });
        let ch: Channel = serde_json::from_value(json).unwrap();
        assert_eq!(ch.id, "UCuAXFkgsw1L7xaCfnd5JJOw");
        let snippet = ch.snippet.unwrap();
        assert_eq!(snippet.custom_url, Some("@rickastley".into()));
        let stats = ch.statistics.unwrap();
        assert_eq!(stats.hidden_subscriber_count, Some(false));
        let cd = ch.content_details.unwrap();
        assert!(cd.related_playlists.is_some());
    }

    // ---- Playlist ----

    #[test]
    fn playlist_serde() {
        let json = json!({
            "kind": "youtube#playlist",
            "etag": "pl_etag",
            "id": "PLrAXtmErZgOeiKm4sgNOknGvNjby9efdf",
            "snippet": {
                "title": "My Playlist",
                "description": "Favorites",
                "publishedAt": "2020-01-01T00:00:00Z"
            },
            "contentDetails": {
                "itemCount": 42
            }
        });
        let pl: Playlist = serde_json::from_value(json).unwrap();
        assert_eq!(pl.content_details.unwrap().item_count, Some(42));
    }

    // ---- PlaylistItem ----

    #[test]
    fn playlist_item_serde() {
        let json = json!({
            "kind": "youtube#playlistItem",
            "etag": "pi_etag",
            "id": "UExYYWIxMjM",
            "snippet": {
                "title": "Song Title",
                "description": "A song",
                "position": 0,
                "resourceId": {
                    "kind": "youtube#video",
                    "videoId": "abc123"
                }
            },
            "contentDetails": {
                "videoId": "abc123",
                "videoPublishedAt": "2020-06-15T12:00:00Z"
            }
        });
        let pi: PlaylistItem = serde_json::from_value(json).unwrap();
        let snippet = pi.snippet.unwrap();
        assert_eq!(snippet.position, Some(0));
        let rid = snippet.resource_id.unwrap();
        assert_eq!(rid.video_id, Some("abc123".into()));
    }

    // ---- CommentThread ----

    #[test]
    fn comment_thread_serde() {
        let json = json!({
            "kind": "youtube#commentThread",
            "etag": "ct_etag",
            "id": "ct_001",
            "snippet": {
                "videoId": "dQw4w9WgXcQ",
                "topLevelComment": {
                    "id": "c_001",
                    "snippet": {
                        "authorDisplayName": "User1",
                        "textDisplay": "Great video!",
                        "likeCount": 42,
                        "publishedAt": "2026-01-01T00:00:00Z"
                    }
                },
                "canReply": true,
                "totalReplyCount": 5,
                "isPublic": true
            }
        });
        let ct: CommentThread = serde_json::from_value(json).unwrap();
        let snippet = ct.snippet.unwrap();
        assert_eq!(snippet.total_reply_count, Some(5));
        let comment = snippet.top_level_comment.unwrap();
        let cs = comment.snippet.unwrap();
        assert_eq!(cs.like_count, Some(42));
    }

    // ---- CaptionTrack ----

    #[test]
    fn caption_track_serde() {
        let json = json!({
            "kind": "youtube#caption",
            "etag": "cap_etag",
            "id": "cap_001",
            "snippet": {
                "videoId": "dQw4w9WgXcQ",
                "language": "en",
                "name": "English",
                "trackKind": "standard",
                "isCc": false,
                "isDraft": false,
                "isAutoSynced": true,
                "status": "serving"
            }
        });
        let ct: CaptionTrack = serde_json::from_value(json).unwrap();
        let snippet = ct.snippet.unwrap();
        assert_eq!(snippet.language, Some("en".into()));
        assert_eq!(snippet.is_cc, Some(false));
        assert_eq!(snippet.is_auto_synced, Some(true));
    }

    // ---- ApiErrorResponse ----

    #[test]
    fn api_error_response_serde() {
        let json = json!({
            "error": {
                "code": 403,
                "message": "The request cannot be completed because you have exceeded your quota.",
                "errors": [{
                    "message": "The request cannot be completed because you have exceeded your quota.",
                    "domain": "youtube.quota",
                    "reason": "quotaExceeded"
                }]
            }
        });
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, Some(403));
        let details = err.errors.unwrap();
        assert_eq!(details[0].reason, Some("quotaExceeded".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let json = json!({});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(resp.error.is_none());
    }

    // ---- ThumbnailSet ----

    #[test]
    fn thumbnail_set_partial() {
        let json = json!({
            "default": {"url": "https://example.com/thumb.jpg", "width": 120, "height": 90},
            "medium": null,
            "high": null
        });
        let ts: ThumbnailSet = serde_json::from_value(json).unwrap();
        assert!(ts.default.is_some());
        assert_eq!(ts.default.unwrap().width, Some(120));
        assert!(ts.medium.is_none());
    }
}
