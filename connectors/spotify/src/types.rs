//! `Spotify` API types.

use serde::{Deserialize, Serialize};

/// A `Spotify` user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub followers: Option<Followers>,
    pub images: Option<Vec<Image>>,
}

/// Follower count from the `Spotify` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Followers {
    pub total: Option<u64>,
}

/// Image object from the `Spotify` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image {
    pub url: Option<String>,
    pub height: Option<u32>,
    pub width: Option<u32>,
}

/// A `Spotify` track.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Track {
    pub id: Option<String>,
    pub name: Option<String>,
    pub artists: Option<Vec<ArtistRef>>,
    pub album: Option<AlbumRef>,
    pub duration_ms: Option<u64>,
    pub explicit: Option<bool>,
    pub uri: Option<String>,
}

/// A simplified artist reference from the `Spotify` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtistRef {
    pub id: Option<String>,
    pub name: Option<String>,
}

/// A simplified album reference from the `Spotify` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlbumRef {
    pub id: Option<String>,
    pub name: Option<String>,
    pub release_date: Option<String>,
}

/// A `Spotify` playlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playlist {
    pub id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub owner: Option<ArtistRef>,
    pub tracks: Option<PlaylistTracks>,
}

/// Playlist track count from the `Spotify` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaylistTracks {
    pub total: Option<u64>,
}

/// `Spotify` API error body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    pub status: Option<u16>,
    pub message: Option<String>,
}

/// `Spotify` API error response wrapper.
///
/// `Spotify` returns `{"error": {"status": 401, "message": "..."}}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiError>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn user_profile_roundtrip() {
        let p: UserProfile = serde_json::from_value(json!({
            "id": "user123",
            "display_name": "Test User",
            "email": "test@example.com",
            "followers": {"total": 42},
            "images": [{"url": "https://i.scdn.co/image/abc", "height": 300, "width": 300}],
        }))
        .unwrap();
        assert_eq!(p.id, Some("user123".into()));
        assert_eq!(p.display_name, Some("Test User".into()));
        assert_eq!(p.email, Some("test@example.com".into()));
        assert_eq!(p.followers.as_ref().unwrap().total, Some(42));
        assert_eq!(p.images.as_ref().unwrap().len(), 1);
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["display_name"], "Test User");
    }

    #[test]
    fn user_profile_minimal() {
        let p: UserProfile = serde_json::from_value(json!({})).unwrap();
        assert!(p.id.is_none());
        assert!(p.display_name.is_none());
        assert!(p.email.is_none());
        assert!(p.followers.is_none());
        assert!(p.images.is_none());
    }

    #[test]
    fn track_roundtrip() {
        let t: Track = serde_json::from_value(json!({
            "id": "track_abc123",
            "name": "Kind of Blue",
            "artists": [{"id": "a1", "name": "Miles Davis"}],
            "album": {"id": "alb1", "name": "Kind of Blue", "release_date": "1959-08-17"},
            "duration_ms": 345000,
            "explicit": false,
            "uri": "spotify:track:track_abc123",
        }))
        .unwrap();
        assert_eq!(t.id, Some("track_abc123".into()));
        assert_eq!(t.name, Some("Kind of Blue".into()));
        assert_eq!(t.artists.as_ref().unwrap().len(), 1);
        assert_eq!(t.artists.as_ref().unwrap()[0].name, Some("Miles Davis".into()));
        assert_eq!(t.album.as_ref().unwrap().name, Some("Kind of Blue".into()));
        assert_eq!(
            t.album.as_ref().unwrap().release_date,
            Some("1959-08-17".into())
        );
        assert_eq!(t.duration_ms, Some(345000));
        assert_eq!(t.explicit, Some(false));
        assert_eq!(t.uri, Some("spotify:track:track_abc123".into()));
        let re = serde_json::to_value(&t).unwrap();
        assert_eq!(re["name"], "Kind of Blue");
    }

    #[test]
    fn track_minimal() {
        let t: Track = serde_json::from_value(json!({})).unwrap();
        assert!(t.id.is_none());
        assert!(t.name.is_none());
        assert!(t.artists.is_none());
        assert!(t.album.is_none());
        assert!(t.duration_ms.is_none());
        assert!(t.explicit.is_none());
        assert!(t.uri.is_none());
    }

    #[test]
    fn track_serialize_roundtrip() {
        let t = Track {
            id: Some("t1".into()),
            name: Some("Song".into()),
            artists: Some(vec![ArtistRef {
                id: Some("a1".into()),
                name: Some("Artist".into()),
            }]),
            album: Some(AlbumRef {
                id: Some("alb1".into()),
                name: Some("Album".into()),
                release_date: Some("2024-01-01".into()),
            }),
            duration_ms: Some(200000),
            explicit: Some(true),
            uri: Some("spotify:track:t1".into()),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["id"], "t1");
        assert_eq!(v["name"], "Song");
        assert_eq!(v["artists"][0]["name"], "Artist");
        assert_eq!(v["album"]["name"], "Album");
    }

    #[test]
    fn artist_ref_roundtrip() {
        let a: ArtistRef = serde_json::from_value(json!({
            "id": "artist_123",
            "name": "Miles Davis",
        }))
        .unwrap();
        assert_eq!(a.id, Some("artist_123".into()));
        assert_eq!(a.name, Some("Miles Davis".into()));
    }

    #[test]
    fn album_ref_roundtrip() {
        let a: AlbumRef = serde_json::from_value(json!({
            "id": "album_456",
            "name": "Kind of Blue",
            "release_date": "1959-08-17",
        }))
        .unwrap();
        assert_eq!(a.id, Some("album_456".into()));
        assert_eq!(a.name, Some("Kind of Blue".into()));
        assert_eq!(a.release_date, Some("1959-08-17".into()));
    }

    #[test]
    fn playlist_roundtrip() {
        let p: Playlist = serde_json::from_value(json!({
            "id": "playlist_789",
            "name": "My Playlist",
            "description": "A test playlist",
            "owner": {"id": "user1", "name": "Test User"},
            "tracks": {"total": 42},
        }))
        .unwrap();
        assert_eq!(p.id, Some("playlist_789".into()));
        assert_eq!(p.name, Some("My Playlist".into()));
        assert_eq!(p.description, Some("A test playlist".into()));
        assert_eq!(p.owner.as_ref().unwrap().name, Some("Test User".into()));
        assert_eq!(p.tracks.as_ref().unwrap().total, Some(42));
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["name"], "My Playlist");
    }

    #[test]
    fn playlist_minimal() {
        let p: Playlist = serde_json::from_value(json!({})).unwrap();
        assert!(p.id.is_none());
        assert!(p.name.is_none());
        assert!(p.description.is_none());
        assert!(p.owner.is_none());
        assert!(p.tracks.is_none());
    }

    #[test]
    fn playlist_tracks_roundtrip() {
        let pt: PlaylistTracks = serde_json::from_value(json!({"total": 100})).unwrap();
        assert_eq!(pt.total, Some(100));
    }

    #[test]
    fn followers_roundtrip() {
        let f: Followers = serde_json::from_value(json!({"total": 1000})).unwrap();
        assert_eq!(f.total, Some(1000));
    }

    #[test]
    fn image_roundtrip() {
        let i: Image = serde_json::from_value(json!({
            "url": "https://i.scdn.co/image/abc",
            "height": 640,
            "width": 640,
        }))
        .unwrap();
        assert_eq!(i.url, Some("https://i.scdn.co/image/abc".into()));
        assert_eq!(i.height, Some(640));
        assert_eq!(i.width, Some(640));
    }

    #[test]
    fn image_minimal() {
        let i: Image = serde_json::from_value(json!({})).unwrap();
        assert!(i.url.is_none());
        assert!(i.height.is_none());
        assert!(i.width.is_none());
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {"status": 401, "message": "Invalid access token"},
        }))
        .unwrap();
        let err = e.error.unwrap();
        assert_eq!(err.status, Some(401));
        assert_eq!(err.message, Some("Invalid access token".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_error_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {"status": 404, "message": "Not found"},
        }))
        .unwrap();
        let err = e.error.unwrap();
        assert_eq!(err.status, Some(404));
        assert_eq!(err.message, Some("Not found".into()));
    }

    #[test]
    fn user_profile_extra_fields_ignored() {
        let p: UserProfile = serde_json::from_value(json!({
            "id": "u1",
            "display_name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(p.id, Some("u1".into()));
        assert_eq!(p.display_name, Some("Test".into()));
    }

    #[test]
    fn track_extra_fields_ignored() {
        let t: Track = serde_json::from_value(json!({
            "id": "t1",
            "name": "Test",
            "popularity": 85,
        }))
        .unwrap();
        assert_eq!(t.id, Some("t1".into()));
        assert_eq!(t.name, Some("Test".into()));
    }

    #[test]
    fn playlist_extra_fields_ignored() {
        let p: Playlist = serde_json::from_value(json!({
            "id": "p1",
            "name": "Test",
            "collaborative": false,
        }))
        .unwrap();
        assert_eq!(p.id, Some("p1".into()));
        assert_eq!(p.name, Some("Test".into()));
    }

    // ── Additional type coverage ─────────────────────────────────

    #[test]
    #[allow(clippy::redundant_clone)]
    fn user_profile_clone() {
        let p = UserProfile {
            id: Some("u1".into()),
            display_name: Some("User".into()),
            email: Some("u@e.com".into()),
            followers: Some(Followers { total: Some(10) }),
            images: Some(vec![Image {
                url: Some("http://img".into()),
                height: Some(300),
                width: Some(300),
            }]),
        };
        let cloned = p.clone();
        assert_eq!(cloned.id, Some("u1".into()));
        assert_eq!(cloned.followers.unwrap().total, Some(10));
        assert_eq!(cloned.images.unwrap().len(), 1);
    }

    #[test]
    fn user_profile_debug() {
        let p = UserProfile {
            id: Some("u1".into()),
            display_name: None,
            email: None,
            followers: None,
            images: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("UserProfile"));
        assert!(dbg.contains("u1"));
    }

    #[test]
    fn followers_minimal() {
        let f: Followers = serde_json::from_value(json!({})).unwrap();
        assert!(f.total.is_none());
    }

    #[test]
    fn followers_clone_debug() {
        let f = Followers { total: Some(42) };
        let cloned = f.clone();
        assert_eq!(cloned.total, Some(42));
        let dbg = format!("{f:?}");
        assert!(dbg.contains("42"));
    }

    #[test]
    fn image_clone_debug() {
        let i = Image {
            url: Some("http://img".into()),
            height: Some(640),
            width: Some(480),
        };
        let cloned = i.clone();
        assert_eq!(cloned.height, Some(640));
        assert_eq!(cloned.width, Some(480));
        let dbg = format!("{i:?}");
        assert!(dbg.contains("640"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn track_clone() {
        let t = Track {
            id: Some("t1".into()),
            name: Some("Song".into()),
            artists: None,
            album: None,
            duration_ms: Some(180_000),
            explicit: Some(false),
            uri: None,
        };
        let cloned = t.clone();
        assert_eq!(cloned.id, Some("t1".into()));
        assert_eq!(cloned.duration_ms, Some(180_000));
    }

    #[test]
    fn track_debug() {
        let t = Track {
            id: Some("t1".into()),
            name: Some("Song".into()),
            artists: None,
            album: None,
            duration_ms: None,
            explicit: None,
            uri: None,
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Track"));
        assert!(dbg.contains("Song"));
    }

    #[test]
    fn artist_ref_minimal() {
        let a: ArtistRef = serde_json::from_value(json!({})).unwrap();
        assert!(a.id.is_none());
        assert!(a.name.is_none());
    }

    #[test]
    fn artist_ref_clone_debug() {
        let a = ArtistRef {
            id: Some("a1".into()),
            name: Some("Miles Davis".into()),
        };
        let cloned = a.clone();
        assert_eq!(cloned.name, Some("Miles Davis".into()));
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Miles Davis"));
    }

    #[test]
    fn album_ref_minimal() {
        let a: AlbumRef = serde_json::from_value(json!({})).unwrap();
        assert!(a.id.is_none());
        assert!(a.name.is_none());
        assert!(a.release_date.is_none());
    }

    #[test]
    fn album_ref_clone_debug() {
        let a = AlbumRef {
            id: Some("alb1".into()),
            name: Some("Album".into()),
            release_date: Some("2024-01-01".into()),
        };
        let cloned = a.clone();
        assert_eq!(cloned.release_date, Some("2024-01-01".into()));
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Album"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn playlist_clone() {
        let p = Playlist {
            id: Some("p1".into()),
            name: Some("My Playlist".into()),
            description: Some("desc".into()),
            owner: Some(ArtistRef {
                id: Some("u1".into()),
                name: Some("User".into()),
            }),
            tracks: Some(PlaylistTracks { total: Some(10) }),
        };
        let cloned = p.clone();
        assert_eq!(cloned.name, Some("My Playlist".into()));
        assert_eq!(cloned.tracks.unwrap().total, Some(10));
    }

    #[test]
    fn playlist_debug() {
        let p = Playlist {
            id: Some("p1".into()),
            name: Some("Test".into()),
            description: None,
            owner: None,
            tracks: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Playlist"));
        assert!(dbg.contains("Test"));
    }

    #[test]
    fn playlist_tracks_minimal() {
        let pt: PlaylistTracks = serde_json::from_value(json!({})).unwrap();
        assert!(pt.total.is_none());
    }

    #[test]
    fn playlist_tracks_clone_debug() {
        let pt = PlaylistTracks { total: Some(99) };
        let cloned = pt.clone();
        assert_eq!(cloned.total, Some(99));
        let dbg = format!("{pt:?}");
        assert!(dbg.contains("99"));
    }

    #[test]
    fn api_error_clone_debug() {
        let e = ApiError {
            status: Some(500),
            message: Some("Internal".into()),
        };
        let cloned = e.clone();
        assert_eq!(cloned.status, Some(500));
        let dbg = format!("{e:?}");
        assert!(dbg.contains("500"));
    }

    #[test]
    fn api_error_minimal() {
        let e: ApiError = serde_json::from_value(json!({})).unwrap();
        assert!(e.status.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_clone_debug() {
        let e = ApiErrorResponse {
            error: Some(ApiError {
                status: Some(401),
                message: Some("Invalid".into()),
            }),
        };
        let cloned = e.clone();
        let inner = cloned.error.unwrap();
        assert_eq!(inner.status, Some(401));
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn user_profile_serialize_full() {
        let p = UserProfile {
            id: Some("u1".into()),
            display_name: Some("Test".into()),
            email: Some("t@t.com".into()),
            followers: Some(Followers { total: Some(5) }),
            images: Some(vec![]),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["id"], "u1");
        assert_eq!(v["followers"]["total"], 5);
    }

    #[test]
    fn track_with_multiple_artists() {
        let t: Track = serde_json::from_value(json!({
            "id": "t1",
            "artists": [
                {"id": "a1", "name": "Artist 1"},
                {"id": "a2", "name": "Artist 2"},
                {"id": "a3", "name": "Artist 3"}
            ]
        }))
        .unwrap();
        assert_eq!(t.artists.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn playlist_serialize_roundtrip() {
        let p = Playlist {
            id: Some("p1".into()),
            name: Some("Test".into()),
            description: None,
            owner: None,
            tracks: Some(PlaylistTracks { total: Some(0) }),
        };
        let v = serde_json::to_value(&p).unwrap();
        let back: Playlist = serde_json::from_value(v).unwrap();
        assert_eq!(back.id, Some("p1".into()));
        assert_eq!(back.tracks.unwrap().total, Some(0));
    }

    #[test]
    fn image_serialize_roundtrip() {
        let i = Image {
            url: Some("https://img.example.com/pic.jpg".into()),
            height: None,
            width: None,
        };
        let v = serde_json::to_value(&i).unwrap();
        let back: Image = serde_json::from_value(v).unwrap();
        assert_eq!(
            back.url,
            Some("https://img.example.com/pic.jpg".into())
        );
        assert!(back.height.is_none());
    }

    #[test]
    fn followers_serialize_roundtrip() {
        let f = Followers { total: Some(0) };
        let v = serde_json::to_value(&f).unwrap();
        let back: Followers = serde_json::from_value(v).unwrap();
        assert_eq!(back.total, Some(0));
    }
}
