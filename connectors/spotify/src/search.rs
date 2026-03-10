//! `Spotify` Search API types and validation.
//!
//! Provides typed search queries, result types, and validation for the
//! `Spotify` Web API search endpoint. Supports discovery across tracks,
//! albums, artists, playlists, shows/podcasts, and episodes.
//!
//! Capability: `spotify.search.read`

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Search type enum ────────────────────────────────────────────────

/// The type of `Spotify` content to search for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchType {
    /// Music tracks.
    Track,
    /// Music albums.
    Album,
    /// Musical artists.
    Artist,
    /// User-created playlists.
    Playlist,
    /// Podcasts / shows.
    Show,
    /// Podcast episodes.
    Episode,
}

impl SearchType {
    /// Returns the `Spotify` API string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Track => "track",
            Self::Album => "album",
            Self::Artist => "artist",
            Self::Playlist => "playlist",
            Self::Show => "show",
            Self::Episode => "episode",
        }
    }

    /// Returns all available search types.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Track,
            Self::Album,
            Self::Artist,
            Self::Playlist,
            Self::Show,
            Self::Episode,
        ]
    }
}

impl fmt::Display for SearchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SearchType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "track" => Ok(Self::Track),
            "album" => Ok(Self::Album),
            "artist" => Ok(Self::Artist),
            "playlist" => Ok(Self::Playlist),
            "show" | "podcast" => Ok(Self::Show),
            "episode" => Ok(Self::Episode),
            other => Err(format!("unknown search type: {other}")),
        }
    }
}

// ── Search query builder ────────────────────────────────────────────

/// A validated search query for the `Spotify` Search API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    /// The search query text.
    pub query: String,
    /// Types of content to search for.
    pub search_types: Vec<SearchType>,
    /// ISO 3166-1 alpha-2 market code.
    pub market: Option<String>,
    /// Maximum number of results per type (1..=50).
    pub limit: u32,
    /// Offset for pagination.
    pub offset: u32,
    /// Whether to include external content (e.g. `"audio"`).
    pub include_external: Option<String>,
}

impl SearchQuery {
    /// Creates a new search query with defaults.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            search_types: vec![SearchType::Track],
            market: None,
            limit: 20,
            offset: 0,
            include_external: None,
        }
    }

    /// Adds a single search type.
    #[must_use]
    pub fn with_type(mut self, search_type: SearchType) -> Self {
        if !self.search_types.contains(&search_type) {
            self.search_types.push(search_type);
        }
        self
    }

    /// Sets the search types, replacing any existing types.
    #[must_use]
    pub fn with_types(mut self, types: Vec<SearchType>) -> Self {
        self.search_types = types;
        self
    }

    /// Sets the market filter.
    #[must_use]
    pub fn with_market(mut self, market: impl Into<String>) -> Self {
        self.market = Some(market.into());
        self
    }

    /// Sets the result limit per type.
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Sets the pagination offset.
    #[must_use]
    pub const fn with_offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }

    /// Sets the `include_external` parameter.
    #[must_use]
    pub fn with_include_external(mut self, external: impl Into<String>) -> Self {
        self.include_external = Some(external.into());
        self
    }

    /// Validates the query against `Spotify` API constraints.
    pub fn validate(&self) -> Result<(), SearchValidationError> {
        SearchValidator::default().validate_query(self)
    }

    /// Builds the comma-separated type string for the API.
    #[must_use]
    pub fn type_string(&self) -> String {
        self.search_types
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

// ── Search results ──────────────────────────────────────────────────

/// Aggregated search results from the `Spotify` Search API.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SearchResults {
    /// Track results, if tracks were requested.
    pub tracks: Option<SearchPage<TrackResult>>,
    /// Album results, if albums were requested.
    pub albums: Option<SearchPage<AlbumResult>>,
    /// Artist results, if artists were requested.
    pub artists: Option<SearchPage<ArtistResult>>,
    /// Playlist results, if playlists were requested.
    pub playlists: Option<SearchPage<PlaylistResult>>,
    /// Show results, if shows/podcasts were requested.
    pub shows: Option<SearchPage<ShowResult>>,
    /// Episode results, if episodes were requested.
    pub episodes: Option<SearchPage<EpisodeResult>>,
}

impl SearchResults {
    /// Returns the total number of results across all types.
    #[must_use]
    pub const fn total_results(&self) -> u64 {
        let mut total: u64 = 0;
        if let Some(ref t) = self.tracks {
            total += t.total;
        }
        if let Some(ref a) = self.albums {
            total += a.total;
        }
        if let Some(ref a) = self.artists {
            total += a.total;
        }
        if let Some(ref p) = self.playlists {
            total += p.total;
        }
        if let Some(ref s) = self.shows {
            total += s.total;
        }
        if let Some(ref e) = self.episodes {
            total += e.total;
        }
        total
    }

    /// Returns true if any result type contains items.
    #[must_use]
    pub fn has_results(&self) -> bool {
        self.tracks.as_ref().is_some_and(|p| !p.is_empty())
            || self.albums.as_ref().is_some_and(|p| !p.is_empty())
            || self.artists.as_ref().is_some_and(|p| !p.is_empty())
            || self.playlists.as_ref().is_some_and(|p| !p.is_empty())
            || self.shows.as_ref().is_some_and(|p| !p.is_empty())
            || self.episodes.as_ref().is_some_and(|p| !p.is_empty())
    }

    /// Returns the types that have results.
    #[must_use]
    pub fn result_types(&self) -> Vec<SearchType> {
        let mut types = Vec::new();
        if self.tracks.as_ref().is_some_and(|p| !p.is_empty()) {
            types.push(SearchType::Track);
        }
        if self.albums.as_ref().is_some_and(|p| !p.is_empty()) {
            types.push(SearchType::Album);
        }
        if self.artists.as_ref().is_some_and(|p| !p.is_empty()) {
            types.push(SearchType::Artist);
        }
        if self.playlists.as_ref().is_some_and(|p| !p.is_empty()) {
            types.push(SearchType::Playlist);
        }
        if self.shows.as_ref().is_some_and(|p| !p.is_empty()) {
            types.push(SearchType::Show);
        }
        if self.episodes.as_ref().is_some_and(|p| !p.is_empty()) {
            types.push(SearchType::Episode);
        }
        types
    }
}

// ── Search page (generic pagination) ────────────────────────────────

/// A paginated page of search results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPage<T> {
    /// The items on this page.
    pub items: Vec<T>,
    /// Total number of matching items across all pages.
    pub total: u64,
    /// Number of items requested.
    pub limit: u32,
    /// Offset of the first item on this page.
    pub offset: u32,
    /// Whether more pages are available.
    pub has_next: bool,
}

impl<T> SearchPage<T> {
    /// Returns true if this page contains no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the offset for the next page, or `None` if no next page.
    #[must_use]
    pub const fn next_offset(&self) -> Option<u32> {
        if self.has_next {
            Some(self.offset + self.limit)
        } else {
            None
        }
    }
}

impl<T> Default for SearchPage<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            total: 0,
            limit: 20,
            offset: 0,
            has_next: false,
        }
    }
}

// ── Result types ────────────────────────────────────────────────────

/// A track result from `Spotify` search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackResult {
    /// `Spotify` track ID.
    pub id: String,
    /// Track name.
    pub name: String,
    /// Artist names.
    pub artists: Vec<String>,
    /// Album name, if available.
    pub album_name: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the track has explicit content.
    pub explicit: bool,
    /// Popularity score (0..=100).
    pub popularity: Option<u32>,
    /// `Spotify` URI.
    pub uri: String,
}

/// An album result from `Spotify` search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlbumResult {
    /// `Spotify` album ID.
    pub id: String,
    /// Album name.
    pub name: String,
    /// Artist names.
    pub artists: Vec<String>,
    /// Release date string (e.g. "2024-01-15").
    pub release_date: Option<String>,
    /// Total number of tracks.
    pub total_tracks: u32,
    /// Album type (e.g. "album", "single", "compilation").
    pub album_type: Option<String>,
    /// `Spotify` URI.
    pub uri: String,
}

/// An artist result from `Spotify` search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtistResult {
    /// `Spotify` artist ID.
    pub id: String,
    /// Artist name.
    pub name: String,
    /// Genres associated with the artist.
    pub genres: Vec<String>,
    /// Popularity score (0..=100).
    pub popularity: Option<u32>,
    /// Total follower count.
    pub followers: Option<u64>,
    /// `Spotify` URI.
    pub uri: String,
}

/// A playlist result from `Spotify` search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaylistResult {
    /// `Spotify` playlist ID.
    pub id: String,
    /// Playlist name.
    pub name: String,
    /// Playlist owner display name.
    pub owner: Option<String>,
    /// Number of tracks in the playlist.
    pub track_count: Option<u32>,
    /// Whether the playlist is public.
    pub public: Option<bool>,
    /// `Spotify` URI.
    pub uri: String,
}

/// A show (podcast) result from `Spotify` search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShowResult {
    /// `Spotify` show ID.
    pub id: String,
    /// Show name.
    pub name: String,
    /// Publisher name.
    pub publisher: Option<String>,
    /// Total number of episodes.
    pub total_episodes: Option<u32>,
    /// `Spotify` URI.
    pub uri: String,
}

/// An episode result from `Spotify` search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeResult {
    /// `Spotify` episode ID.
    pub id: String,
    /// Episode name.
    pub name: String,
    /// Name of the parent show.
    pub show_name: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Release date string.
    pub release_date: Option<String>,
    /// `Spotify` URI.
    pub uri: String,
}

// ── Validation ──────────────────────────────────────────────────────

/// Validation errors for `Spotify` search queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchValidationError {
    /// Query string is empty.
    EmptyQuery,
    /// Query exceeds maximum allowed length.
    QueryTooLong {
        /// The actual length.
        length: usize,
        /// The maximum allowed length.
        max: usize,
    },
    /// Limit is out of the valid range.
    InvalidLimit {
        /// The provided limit.
        value: u32,
        /// The maximum allowed limit.
        max: u32,
    },
    /// No search types were specified.
    NoSearchTypes,
    /// Offset exceeds maximum allowed value.
    InvalidOffset {
        /// The provided offset.
        value: u32,
    },
}

impl fmt::Display for SearchValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyQuery => write!(f, "search query must not be empty"),
            Self::QueryTooLong { length, max } => {
                write!(f, "query length {length} exceeds maximum {max}")
            }
            Self::InvalidLimit { value, max } => {
                write!(f, "limit {value} is invalid (must be 1..={max})")
            }
            Self::NoSearchTypes => write!(f, "at least one search type must be specified"),
            Self::InvalidOffset { value } => {
                write!(f, "offset {value} exceeds maximum allowed value")
            }
        }
    }
}

impl std::error::Error for SearchValidationError {}

/// Validates `Spotify` search queries against API constraints.
#[derive(Debug, Clone)]
pub struct SearchValidator {
    /// Maximum query string length.
    pub max_query_length: usize,
    /// Maximum results per page.
    pub max_limit: u32,
    /// Maximum pagination offset.
    pub max_offset: u32,
    /// Allowed search types.
    pub allowed_types: Vec<SearchType>,
}

impl Default for SearchValidator {
    fn default() -> Self {
        Self {
            max_query_length: 256,
            max_limit: 50,
            max_offset: 1000,
            allowed_types: SearchType::all().to_vec(),
        }
    }
}

impl SearchValidator {
    /// Validates a search query.
    pub fn validate_query(&self, query: &SearchQuery) -> Result<(), SearchValidationError> {
        if query.query.trim().is_empty() {
            return Err(SearchValidationError::EmptyQuery);
        }
        if query.query.len() > self.max_query_length {
            return Err(SearchValidationError::QueryTooLong {
                length: query.query.len(),
                max: self.max_query_length,
            });
        }
        if query.search_types.is_empty() {
            return Err(SearchValidationError::NoSearchTypes);
        }
        if query.limit == 0 || query.limit > self.max_limit {
            return Err(SearchValidationError::InvalidLimit {
                value: query.limit,
                max: self.max_limit,
            });
        }
        if query.offset > self.max_offset {
            return Err(SearchValidationError::InvalidOffset {
                value: query.offset,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SearchType tests ────────────────────────────────────────────

    #[test]
    fn search_type_as_str_track() {
        assert_eq!(SearchType::Track.as_str(), "track");
    }

    #[test]
    fn search_type_as_str_album() {
        assert_eq!(SearchType::Album.as_str(), "album");
    }

    #[test]
    fn search_type_as_str_artist() {
        assert_eq!(SearchType::Artist.as_str(), "artist");
    }

    #[test]
    fn search_type_as_str_playlist() {
        assert_eq!(SearchType::Playlist.as_str(), "playlist");
    }

    #[test]
    fn search_type_as_str_show() {
        assert_eq!(SearchType::Show.as_str(), "show");
    }

    #[test]
    fn search_type_as_str_episode() {
        assert_eq!(SearchType::Episode.as_str(), "episode");
    }

    #[test]
    fn search_type_from_str_track() {
        assert_eq!("track".parse::<SearchType>().unwrap(), SearchType::Track);
    }

    #[test]
    fn search_type_from_str_album() {
        assert_eq!("album".parse::<SearchType>().unwrap(), SearchType::Album);
    }

    #[test]
    fn search_type_from_str_artist() {
        assert_eq!("artist".parse::<SearchType>().unwrap(), SearchType::Artist);
    }

    #[test]
    fn search_type_from_str_playlist() {
        assert_eq!(
            "playlist".parse::<SearchType>().unwrap(),
            SearchType::Playlist
        );
    }

    #[test]
    fn search_type_from_str_show() {
        assert_eq!("show".parse::<SearchType>().unwrap(), SearchType::Show);
    }

    #[test]
    fn search_type_from_str_podcast_alias() {
        assert_eq!("podcast".parse::<SearchType>().unwrap(), SearchType::Show);
    }

    #[test]
    fn search_type_from_str_episode() {
        assert_eq!(
            "episode".parse::<SearchType>().unwrap(),
            SearchType::Episode
        );
    }

    #[test]
    fn search_type_from_str_case_insensitive() {
        assert_eq!("Track".parse::<SearchType>().unwrap(), SearchType::Track);
        assert_eq!("ALBUM".parse::<SearchType>().unwrap(), SearchType::Album);
        assert_eq!("Artist".parse::<SearchType>().unwrap(), SearchType::Artist);
        assert_eq!(
            "PLAYLIST".parse::<SearchType>().unwrap(),
            SearchType::Playlist
        );
        assert_eq!("Show".parse::<SearchType>().unwrap(), SearchType::Show);
        assert_eq!(
            "EPISODE".parse::<SearchType>().unwrap(),
            SearchType::Episode
        );
    }

    #[test]
    fn search_type_from_str_invalid() {
        let result = "invalid".parse::<SearchType>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown search type"));
    }

    #[test]
    fn search_type_display() {
        assert_eq!(SearchType::Track.to_string(), "track");
        assert_eq!(SearchType::Album.to_string(), "album");
        assert_eq!(SearchType::Artist.to_string(), "artist");
        assert_eq!(SearchType::Playlist.to_string(), "playlist");
        assert_eq!(SearchType::Show.to_string(), "show");
        assert_eq!(SearchType::Episode.to_string(), "episode");
    }

    #[test]
    fn search_type_all() {
        let all = SearchType::all();
        assert_eq!(all.len(), 6);
        assert!(all.contains(&SearchType::Track));
        assert!(all.contains(&SearchType::Episode));
    }

    #[test]
    fn search_type_equality() {
        assert_eq!(SearchType::Track, SearchType::Track);
        assert_ne!(SearchType::Track, SearchType::Album);
    }

    #[test]
    fn search_type_clone() {
        let t = SearchType::Artist;
        let cloned = t;
        assert_eq!(cloned, SearchType::Artist);
    }

    #[test]
    fn search_type_debug() {
        let dbg = format!("{:?}", SearchType::Track);
        assert!(dbg.contains("Track"));
    }

    #[test]
    fn search_type_serde_roundtrip() {
        let t = SearchType::Playlist;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"playlist\"");
        let back: SearchType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SearchType::Playlist);
    }

    #[test]
    fn search_type_serde_all_variants() {
        for st in SearchType::all() {
            let json = serde_json::to_string(st).unwrap();
            let back: SearchType = serde_json::from_str(&json).unwrap();
            assert_eq!(*st, back);
        }
    }

    #[test]
    fn search_type_hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SearchType::Track);
        set.insert(SearchType::Track);
        set.insert(SearchType::Album);
        assert_eq!(set.len(), 2);
    }

    // ── SearchQuery builder tests ───────────────────────────────────

    #[test]
    fn query_new_defaults() {
        let q = SearchQuery::new("test");
        assert_eq!(q.query, "test");
        assert_eq!(q.search_types, vec![SearchType::Track]);
        assert!(q.market.is_none());
        assert_eq!(q.limit, 20);
        assert_eq!(q.offset, 0);
        assert!(q.include_external.is_none());
    }

    #[test]
    fn query_with_type_adds_type() {
        let q = SearchQuery::new("test").with_type(SearchType::Album);
        assert_eq!(q.search_types.len(), 2);
        assert!(q.search_types.contains(&SearchType::Track));
        assert!(q.search_types.contains(&SearchType::Album));
    }

    #[test]
    fn query_with_type_no_duplicate() {
        let q = SearchQuery::new("test").with_type(SearchType::Track);
        assert_eq!(q.search_types.len(), 1);
    }

    #[test]
    fn query_with_types_replaces() {
        let q = SearchQuery::new("test").with_types(vec![SearchType::Artist, SearchType::Album]);
        assert_eq!(q.search_types.len(), 2);
        assert!(!q.search_types.contains(&SearchType::Track));
    }

    #[test]
    fn query_with_market() {
        let q = SearchQuery::new("test").with_market("US");
        assert_eq!(q.market, Some("US".into()));
    }

    #[test]
    fn query_with_limit() {
        let q = SearchQuery::new("test").with_limit(50);
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn query_with_offset() {
        let q = SearchQuery::new("test").with_offset(100);
        assert_eq!(q.offset, 100);
    }

    #[test]
    fn query_with_include_external() {
        let q = SearchQuery::new("test").with_include_external("audio");
        assert_eq!(q.include_external, Some("audio".into()));
    }

    #[test]
    fn query_builder_chaining() {
        let q = SearchQuery::new("jazz")
            .with_type(SearchType::Album)
            .with_type(SearchType::Artist)
            .with_market("GB")
            .with_limit(10)
            .with_offset(20)
            .with_include_external("audio");
        assert_eq!(q.query, "jazz");
        assert_eq!(q.search_types.len(), 3);
        assert_eq!(q.market, Some("GB".into()));
        assert_eq!(q.limit, 10);
        assert_eq!(q.offset, 20);
        assert_eq!(q.include_external, Some("audio".into()));
    }

    #[test]
    fn query_type_string_single() {
        let q = SearchQuery::new("test");
        assert_eq!(q.type_string(), "track");
    }

    #[test]
    fn query_type_string_multiple() {
        let q = SearchQuery::new("test").with_types(vec![
            SearchType::Track,
            SearchType::Album,
            SearchType::Artist,
        ]);
        assert_eq!(q.type_string(), "track,album,artist");
    }

    #[test]
    fn query_validate_valid() {
        let q = SearchQuery::new("test");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_empty() {
        let q = SearchQuery::new("");
        assert!(matches!(
            q.validate(),
            Err(SearchValidationError::EmptyQuery)
        ));
    }

    #[test]
    fn query_validate_whitespace_only() {
        let q = SearchQuery::new("   ");
        assert!(matches!(
            q.validate(),
            Err(SearchValidationError::EmptyQuery)
        ));
    }

    #[test]
    fn query_validate_too_long() {
        let long = "a".repeat(257);
        let q = SearchQuery::new(long);
        assert!(matches!(
            q.validate(),
            Err(SearchValidationError::QueryTooLong { .. })
        ));
    }

    #[test]
    fn query_validate_exactly_max_length() {
        let exact = "a".repeat(256);
        let q = SearchQuery::new(exact);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_no_types() {
        let q = SearchQuery::new("test").with_types(vec![]);
        assert!(matches!(
            q.validate(),
            Err(SearchValidationError::NoSearchTypes)
        ));
    }

    #[test]
    fn query_validate_zero_limit() {
        let q = SearchQuery::new("test").with_limit(0);
        assert!(matches!(
            q.validate(),
            Err(SearchValidationError::InvalidLimit { .. })
        ));
    }

    #[test]
    fn query_validate_limit_over_max() {
        let q = SearchQuery::new("test").with_limit(51);
        assert!(matches!(
            q.validate(),
            Err(SearchValidationError::InvalidLimit { .. })
        ));
    }

    #[test]
    fn query_validate_limit_at_max() {
        let q = SearchQuery::new("test").with_limit(50);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_offset_over_max() {
        let q = SearchQuery::new("test").with_offset(1001);
        assert!(matches!(
            q.validate(),
            Err(SearchValidationError::InvalidOffset { .. })
        ));
    }

    #[test]
    fn query_validate_offset_at_max() {
        let q = SearchQuery::new("test").with_offset(1000);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_serde_roundtrip() {
        let q = SearchQuery::new("test query")
            .with_type(SearchType::Album)
            .with_market("US")
            .with_limit(10)
            .with_offset(5)
            .with_include_external("audio");
        let json = serde_json::to_value(&q).unwrap();
        let back: SearchQuery = serde_json::from_value(json).unwrap();
        assert_eq!(back.query, "test query");
        assert_eq!(back.limit, 10);
        assert_eq!(back.offset, 5);
        assert_eq!(back.market, Some("US".into()));
        assert_eq!(back.include_external, Some("audio".into()));
    }

    #[test]
    fn query_debug() {
        let q = SearchQuery::new("debug test");
        let dbg = format!("{q:?}");
        assert!(dbg.contains("SearchQuery"));
        assert!(dbg.contains("debug test"));
    }

    #[test]
    fn query_clone() {
        let q = SearchQuery::new("clone test").with_market("DE");
        let cloned = q.clone();
        assert_eq!(q.query, cloned.query);
        assert_eq!(q.market, cloned.market);
    }

    // ── SearchPage tests ────────────────────────────────────────────

    #[test]
    fn page_is_empty_true() {
        let page: SearchPage<TrackResult> = SearchPage::default();
        assert!(page.is_empty());
    }

    #[test]
    fn page_is_empty_false() {
        let page = SearchPage {
            items: vec![make_track("t1", "Song")],
            total: 1,
            limit: 20,
            offset: 0,
            has_next: false,
        };
        assert!(!page.is_empty());
    }

    #[test]
    fn page_next_offset_has_next() {
        let page: SearchPage<TrackResult> = SearchPage {
            items: vec![],
            total: 100,
            limit: 20,
            offset: 0,
            has_next: true,
        };
        assert_eq!(page.next_offset(), Some(20));
    }

    #[test]
    fn page_next_offset_no_next() {
        let page: SearchPage<TrackResult> = SearchPage {
            items: vec![],
            total: 10,
            limit: 20,
            offset: 0,
            has_next: false,
        };
        assert_eq!(page.next_offset(), None);
    }

    #[test]
    fn page_next_offset_second_page() {
        let page: SearchPage<TrackResult> = SearchPage {
            items: vec![],
            total: 100,
            limit: 20,
            offset: 20,
            has_next: true,
        };
        assert_eq!(page.next_offset(), Some(40));
    }

    #[test]
    fn page_default_values() {
        let page: SearchPage<AlbumResult> = SearchPage::default();
        assert!(page.items.is_empty());
        assert_eq!(page.total, 0);
        assert_eq!(page.limit, 20);
        assert_eq!(page.offset, 0);
        assert!(!page.has_next);
    }

    #[test]
    fn page_clone() {
        let page = SearchPage {
            items: vec![make_track("t1", "Song")],
            total: 1,
            limit: 20,
            offset: 0,
            has_next: false,
        };
        let cloned = page.clone();
        assert_eq!(page.items.len(), cloned.items.len());
        assert_eq!(page.total, cloned.total);
    }

    #[test]
    fn page_debug() {
        let page: SearchPage<TrackResult> = SearchPage::default();
        let dbg = format!("{page:?}");
        assert!(dbg.contains("SearchPage"));
    }

    #[test]
    fn page_serde_roundtrip() {
        let page = SearchPage {
            items: vec![make_track("t1", "Track One")],
            total: 42,
            limit: 10,
            offset: 5,
            has_next: true,
        };
        let json = serde_json::to_value(&page).unwrap();
        let back: SearchPage<TrackResult> = serde_json::from_value(json).unwrap();
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.total, 42);
        assert_eq!(back.limit, 10);
        assert_eq!(back.offset, 5);
        assert!(back.has_next);
    }

    // ── SearchResults tests ─────────────────────────────────────────

    #[test]
    fn results_default_empty() {
        let r = SearchResults::default();
        assert_eq!(r.total_results(), 0);
        assert!(!r.has_results());
        assert!(r.result_types().is_empty());
    }

    #[test]
    fn results_total_tracks_only() {
        let r = SearchResults {
            tracks: Some(SearchPage {
                items: vec![make_track("t1", "Song")],
                total: 100,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        assert_eq!(r.total_results(), 100);
    }

    #[test]
    fn results_total_multiple_types() {
        let r = SearchResults {
            tracks: Some(SearchPage {
                items: vec![],
                total: 50,
                ..SearchPage::default()
            }),
            albums: Some(SearchPage {
                items: vec![],
                total: 30,
                ..SearchPage::default()
            }),
            artists: Some(SearchPage {
                items: vec![],
                total: 20,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        assert_eq!(r.total_results(), 100);
    }

    #[test]
    fn results_total_all_types() {
        let r = SearchResults {
            tracks: Some(SearchPage {
                items: vec![],
                total: 10,
                ..SearchPage::default()
            }),
            albums: Some(SearchPage {
                items: vec![],
                total: 20,
                ..SearchPage::default()
            }),
            artists: Some(SearchPage {
                items: vec![],
                total: 30,
                ..SearchPage::default()
            }),
            playlists: Some(SearchPage {
                items: vec![],
                total: 40,
                ..SearchPage::default()
            }),
            shows: Some(SearchPage {
                items: vec![],
                total: 50,
                ..SearchPage::default()
            }),
            episodes: Some(SearchPage {
                items: vec![],
                total: 60,
                ..SearchPage::default()
            }),
        };
        assert_eq!(r.total_results(), 210);
    }

    #[test]
    fn results_has_results_true() {
        let r = SearchResults {
            tracks: Some(SearchPage {
                items: vec![make_track("t1", "S")],
                total: 1,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        assert!(r.has_results());
    }

    #[test]
    fn results_has_results_false_empty_page() {
        let r = SearchResults {
            tracks: Some(SearchPage::default()),
            ..SearchResults::default()
        };
        assert!(!r.has_results());
    }

    #[test]
    fn results_result_types_single() {
        let r = SearchResults {
            artists: Some(SearchPage {
                items: vec![make_artist("a1", "Art")],
                total: 1,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        assert_eq!(r.result_types(), vec![SearchType::Artist]);
    }

    #[test]
    fn results_result_types_multiple() {
        let r = SearchResults {
            tracks: Some(SearchPage {
                items: vec![make_track("t1", "S")],
                total: 1,
                ..SearchPage::default()
            }),
            playlists: Some(SearchPage {
                items: vec![make_playlist("p1", "P")],
                total: 1,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        let types = r.result_types();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&SearchType::Track));
        assert!(types.contains(&SearchType::Playlist));
    }

    #[test]
    fn results_result_types_all() {
        let r = SearchResults {
            tracks: Some(SearchPage {
                items: vec![make_track("t1", "T")],
                total: 1,
                ..SearchPage::default()
            }),
            albums: Some(SearchPage {
                items: vec![make_album("a1", "A")],
                total: 1,
                ..SearchPage::default()
            }),
            artists: Some(SearchPage {
                items: vec![make_artist("ar1", "Ar")],
                total: 1,
                ..SearchPage::default()
            }),
            playlists: Some(SearchPage {
                items: vec![make_playlist("p1", "P")],
                total: 1,
                ..SearchPage::default()
            }),
            shows: Some(SearchPage {
                items: vec![make_show("s1", "S")],
                total: 1,
                ..SearchPage::default()
            }),
            episodes: Some(SearchPage {
                items: vec![make_episode("e1", "E")],
                total: 1,
                ..SearchPage::default()
            }),
        };
        assert_eq!(r.result_types().len(), 6);
    }

    #[test]
    fn results_serde_roundtrip() {
        let r = SearchResults {
            tracks: Some(SearchPage {
                items: vec![make_track("t1", "Song")],
                total: 1,
                limit: 20,
                offset: 0,
                has_next: false,
            }),
            ..SearchResults::default()
        };
        let json = serde_json::to_value(&r).unwrap();
        let back: SearchResults = serde_json::from_value(json).unwrap();
        assert_eq!(back.tracks.as_ref().unwrap().items.len(), 1);
        assert!(back.albums.is_none());
    }

    #[test]
    fn results_clone() {
        let r = SearchResults {
            tracks: Some(SearchPage {
                items: vec![make_track("t1", "S")],
                total: 1,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        let cloned = r.clone();
        assert!(r.has_results());
        assert!(cloned.has_results());
    }

    #[test]
    fn results_debug() {
        let r = SearchResults::default();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("SearchResults"));
    }

    // ── TrackResult tests ───────────────────────────────────────────

    #[test]
    fn track_result_fields() {
        let t = make_track("t1", "Kind of Blue");
        assert_eq!(t.id, "t1");
        assert_eq!(t.name, "Kind of Blue");
        assert_eq!(t.artists, vec!["Miles Davis"]);
        assert_eq!(t.album_name, Some("Album".into()));
        assert_eq!(t.duration_ms, 345_000);
        assert!(!t.explicit);
        assert_eq!(t.popularity, Some(85));
        assert_eq!(t.uri, "spotify:track:t1");
    }

    #[test]
    fn track_result_serde_roundtrip() {
        let t = make_track("t1", "Song");
        let json = serde_json::to_value(&t).unwrap();
        let back: TrackResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "t1");
        assert_eq!(back.name, "Song");
    }

    #[test]
    fn track_result_debug() {
        let t = make_track("t1", "Song");
        let dbg = format!("{t:?}");
        assert!(dbg.contains("TrackResult"));
        assert!(dbg.contains("Song"));
    }

    #[test]
    fn track_result_clone() {
        let t = make_track("t1", "Song");
        let cloned = t.clone();
        assert_eq!(t.id, cloned.id);
        assert_eq!(t.artists.len(), cloned.artists.len());
    }

    #[test]
    fn track_result_no_album() {
        let t = TrackResult {
            id: "t1".into(),
            name: "Song".into(),
            artists: vec![],
            album_name: None,
            duration_ms: 100_000,
            explicit: false,
            popularity: None,
            uri: "spotify:track:t1".into(),
        };
        assert!(t.album_name.is_none());
        assert!(t.popularity.is_none());
    }

    #[test]
    fn track_result_multiple_artists() {
        let t = TrackResult {
            id: "t1".into(),
            name: "Collab".into(),
            artists: vec!["A".into(), "B".into(), "C".into()],
            album_name: None,
            duration_ms: 200_000,
            explicit: true,
            popularity: None,
            uri: "spotify:track:t1".into(),
        };
        assert_eq!(t.artists.len(), 3);
        assert!(t.explicit);
    }

    // ── AlbumResult tests ───────────────────────────────────────────

    #[test]
    fn album_result_fields() {
        let a = make_album("a1", "Kind of Blue");
        assert_eq!(a.id, "a1");
        assert_eq!(a.name, "Kind of Blue");
        assert_eq!(a.artists, vec!["Miles Davis"]);
        assert_eq!(a.release_date, Some("1959-08-17".into()));
        assert_eq!(a.total_tracks, 5);
        assert_eq!(a.album_type, Some("album".into()));
        assert_eq!(a.uri, "spotify:album:a1");
    }

    #[test]
    fn album_result_serde_roundtrip() {
        let a = make_album("a1", "Album");
        let json = serde_json::to_value(&a).unwrap();
        let back: AlbumResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "a1");
        assert_eq!(back.total_tracks, 5);
    }

    #[test]
    fn album_result_debug() {
        let a = make_album("a1", "Album");
        let dbg = format!("{a:?}");
        assert!(dbg.contains("AlbumResult"));
    }

    #[test]
    fn album_result_clone() {
        let a = make_album("a1", "Album");
        let cloned = a.clone();
        assert_eq!(a.name, cloned.name);
    }

    #[test]
    fn album_result_single_type() {
        let a = AlbumResult {
            id: "a1".into(),
            name: "Single".into(),
            artists: vec!["Artist".into()],
            release_date: None,
            total_tracks: 1,
            album_type: Some("single".into()),
            uri: "spotify:album:a1".into(),
        };
        assert_eq!(a.album_type, Some("single".into()));
    }

    // ── ArtistResult tests ──────────────────────────────────────────

    #[test]
    fn artist_result_fields() {
        let a = make_artist("ar1", "Miles Davis");
        assert_eq!(a.id, "ar1");
        assert_eq!(a.name, "Miles Davis");
        assert_eq!(a.genres, vec!["jazz"]);
        assert_eq!(a.popularity, Some(78));
        assert_eq!(a.followers, Some(5_000_000));
        assert_eq!(a.uri, "spotify:artist:ar1");
    }

    #[test]
    fn artist_result_serde_roundtrip() {
        let a = make_artist("ar1", "Artist");
        let json = serde_json::to_value(&a).unwrap();
        let back: ArtistResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "ar1");
    }

    #[test]
    fn artist_result_debug() {
        let a = make_artist("ar1", "Artist");
        let dbg = format!("{a:?}");
        assert!(dbg.contains("ArtistResult"));
    }

    #[test]
    fn artist_result_clone() {
        let a = make_artist("ar1", "Artist");
        let cloned = a.clone();
        assert_eq!(a.genres.len(), cloned.genres.len());
    }

    #[test]
    fn artist_result_no_genres() {
        let a = ArtistResult {
            id: "ar1".into(),
            name: "New Artist".into(),
            genres: vec![],
            popularity: None,
            followers: None,
            uri: "spotify:artist:ar1".into(),
        };
        assert!(a.genres.is_empty());
        assert!(a.popularity.is_none());
        assert!(a.followers.is_none());
    }

    #[test]
    fn artist_result_multiple_genres() {
        let a = ArtistResult {
            id: "ar1".into(),
            name: "Multi".into(),
            genres: vec!["jazz".into(), "blues".into(), "soul".into()],
            popularity: Some(90),
            followers: Some(10_000_000),
            uri: "spotify:artist:ar1".into(),
        };
        assert_eq!(a.genres.len(), 3);
    }

    // ── PlaylistResult tests ────────────────────────────────────────

    #[test]
    fn playlist_result_fields() {
        let p = make_playlist("p1", "Chill Vibes");
        assert_eq!(p.id, "p1");
        assert_eq!(p.name, "Chill Vibes");
        assert_eq!(p.owner, Some("DJ Cool".into()));
        assert_eq!(p.track_count, Some(42));
        assert_eq!(p.public, Some(true));
        assert_eq!(p.uri, "spotify:playlist:p1");
    }

    #[test]
    fn playlist_result_serde_roundtrip() {
        let p = make_playlist("p1", "Playlist");
        let json = serde_json::to_value(&p).unwrap();
        let back: PlaylistResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "p1");
    }

    #[test]
    fn playlist_result_debug() {
        let p = make_playlist("p1", "Playlist");
        let dbg = format!("{p:?}");
        assert!(dbg.contains("PlaylistResult"));
    }

    #[test]
    fn playlist_result_clone() {
        let p = make_playlist("p1", "Playlist");
        let cloned = p.clone();
        assert_eq!(p.name, cloned.name);
    }

    #[test]
    fn playlist_result_private() {
        let p = PlaylistResult {
            id: "p1".into(),
            name: "Private".into(),
            owner: None,
            track_count: None,
            public: Some(false),
            uri: "spotify:playlist:p1".into(),
        };
        assert_eq!(p.public, Some(false));
        assert!(p.owner.is_none());
    }

    // ── ShowResult tests ────────────────────────────────────────────

    #[test]
    fn show_result_fields() {
        let s = make_show("s1", "Tech Talk");
        assert_eq!(s.id, "s1");
        assert_eq!(s.name, "Tech Talk");
        assert_eq!(s.publisher, Some("Publisher Co".into()));
        assert_eq!(s.total_episodes, Some(100));
        assert_eq!(s.uri, "spotify:show:s1");
    }

    #[test]
    fn show_result_serde_roundtrip() {
        let s = make_show("s1", "Show");
        let json = serde_json::to_value(&s).unwrap();
        let back: ShowResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "s1");
    }

    #[test]
    fn show_result_debug() {
        let s = make_show("s1", "Show");
        let dbg = format!("{s:?}");
        assert!(dbg.contains("ShowResult"));
    }

    #[test]
    fn show_result_clone() {
        let s = make_show("s1", "Show");
        let cloned = s.clone();
        assert_eq!(s.name, cloned.name);
    }

    #[test]
    fn show_result_minimal() {
        let s = ShowResult {
            id: "s1".into(),
            name: "Minimal".into(),
            publisher: None,
            total_episodes: None,
            uri: "spotify:show:s1".into(),
        };
        assert!(s.publisher.is_none());
        assert!(s.total_episodes.is_none());
    }

    // ── EpisodeResult tests ─────────────────────────────────────────

    #[test]
    fn episode_result_fields() {
        let e = make_episode("e1", "Ep 1");
        assert_eq!(e.id, "e1");
        assert_eq!(e.name, "Ep 1");
        assert_eq!(e.show_name, Some("Parent Show".into()));
        assert_eq!(e.duration_ms, 1_800_000);
        assert_eq!(e.release_date, Some("2024-06-01".into()));
        assert_eq!(e.uri, "spotify:episode:e1");
    }

    #[test]
    fn episode_result_serde_roundtrip() {
        let e = make_episode("e1", "Episode");
        let json = serde_json::to_value(&e).unwrap();
        let back: EpisodeResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "e1");
    }

    #[test]
    fn episode_result_debug() {
        let e = make_episode("e1", "Episode");
        let dbg = format!("{e:?}");
        assert!(dbg.contains("EpisodeResult"));
    }

    #[test]
    fn episode_result_clone() {
        let e = make_episode("e1", "Episode");
        let cloned = e.clone();
        assert_eq!(e.name, cloned.name);
    }

    #[test]
    fn episode_result_minimal() {
        let e = EpisodeResult {
            id: "e1".into(),
            name: "Minimal".into(),
            show_name: None,
            duration_ms: 60_000,
            release_date: None,
            uri: "spotify:episode:e1".into(),
        };
        assert!(e.show_name.is_none());
        assert!(e.release_date.is_none());
    }

    // ── SearchValidator tests ───────────────────────────────────────

    #[test]
    fn validator_default() {
        let v = SearchValidator::default();
        assert_eq!(v.max_query_length, 256);
        assert_eq!(v.max_limit, 50);
        assert_eq!(v.max_offset, 1000);
        assert_eq!(v.allowed_types.len(), 6);
    }

    #[test]
    fn validator_accepts_valid_query() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("test");
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validator_rejects_empty_query() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("");
        assert_eq!(
            v.validate_query(&q).unwrap_err(),
            SearchValidationError::EmptyQuery
        );
    }

    #[test]
    fn validator_rejects_whitespace_query() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("  \t\n  ");
        assert_eq!(
            v.validate_query(&q).unwrap_err(),
            SearchValidationError::EmptyQuery
        );
    }

    #[test]
    fn validator_rejects_long_query() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("x".repeat(257));
        match v.validate_query(&q).unwrap_err() {
            SearchValidationError::QueryTooLong { length, max } => {
                assert_eq!(length, 257);
                assert_eq!(max, 256);
            }
            other => panic!("expected QueryTooLong, got {other:?}"),
        }
    }

    #[test]
    fn validator_rejects_no_types() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("test").with_types(vec![]);
        assert_eq!(
            v.validate_query(&q).unwrap_err(),
            SearchValidationError::NoSearchTypes
        );
    }

    #[test]
    fn validator_rejects_zero_limit() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("test").with_limit(0);
        match v.validate_query(&q).unwrap_err() {
            SearchValidationError::InvalidLimit { value, max } => {
                assert_eq!(value, 0);
                assert_eq!(max, 50);
            }
            other => panic!("expected InvalidLimit, got {other:?}"),
        }
    }

    #[test]
    fn validator_rejects_large_limit() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("test").with_limit(100);
        match v.validate_query(&q).unwrap_err() {
            SearchValidationError::InvalidLimit { value, max } => {
                assert_eq!(value, 100);
                assert_eq!(max, 50);
            }
            other => panic!("expected InvalidLimit, got {other:?}"),
        }
    }

    #[test]
    fn validator_rejects_large_offset() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("test").with_offset(2000);
        match v.validate_query(&q).unwrap_err() {
            SearchValidationError::InvalidOffset { value } => {
                assert_eq!(value, 2000);
            }
            other => panic!("expected InvalidOffset, got {other:?}"),
        }
    }

    #[test]
    fn validator_custom_limits() {
        let v = SearchValidator {
            max_query_length: 50,
            max_limit: 10,
            max_offset: 100,
            allowed_types: vec![SearchType::Track],
        };
        let q = SearchQuery::new("x".repeat(51));
        assert!(matches!(
            v.validate_query(&q).unwrap_err(),
            SearchValidationError::QueryTooLong { .. }
        ));

        let q = SearchQuery::new("ok").with_limit(11);
        assert!(matches!(
            v.validate_query(&q).unwrap_err(),
            SearchValidationError::InvalidLimit { .. }
        ));

        let q = SearchQuery::new("ok").with_limit(5).with_offset(101);
        assert!(matches!(
            v.validate_query(&q).unwrap_err(),
            SearchValidationError::InvalidOffset { .. }
        ));
    }

    #[test]
    fn validator_clone() {
        let v = SearchValidator::default();
        let cloned = v.clone();
        assert_eq!(v.max_query_length, cloned.max_query_length);
    }

    #[test]
    fn validator_debug() {
        let v = SearchValidator::default();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("SearchValidator"));
    }

    // ── SearchValidationError tests ─────────────────────────────────

    #[test]
    fn validation_error_display_empty() {
        let e = SearchValidationError::EmptyQuery;
        assert_eq!(e.to_string(), "search query must not be empty");
    }

    #[test]
    fn validation_error_display_too_long() {
        let e = SearchValidationError::QueryTooLong {
            length: 300,
            max: 256,
        };
        assert_eq!(e.to_string(), "query length 300 exceeds maximum 256");
    }

    #[test]
    fn validation_error_display_invalid_limit() {
        let e = SearchValidationError::InvalidLimit { value: 0, max: 50 };
        assert_eq!(e.to_string(), "limit 0 is invalid (must be 1..=50)");
    }

    #[test]
    fn validation_error_display_no_types() {
        let e = SearchValidationError::NoSearchTypes;
        assert_eq!(e.to_string(), "at least one search type must be specified");
    }

    #[test]
    fn validation_error_display_invalid_offset() {
        let e = SearchValidationError::InvalidOffset { value: 5000 };
        assert_eq!(e.to_string(), "offset 5000 exceeds maximum allowed value");
    }

    #[test]
    fn validation_error_eq() {
        assert_eq!(
            SearchValidationError::EmptyQuery,
            SearchValidationError::EmptyQuery
        );
        assert_ne!(
            SearchValidationError::EmptyQuery,
            SearchValidationError::NoSearchTypes
        );
    }

    #[test]
    fn validation_error_clone() {
        let e = SearchValidationError::QueryTooLong {
            length: 300,
            max: 256,
        };
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn validation_error_debug() {
        let e = SearchValidationError::EmptyQuery;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("EmptyQuery"));
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let e = SearchValidationError::QueryTooLong {
            length: 300,
            max: 256,
        };
        let json = serde_json::to_value(&e).unwrap();
        let back: SearchValidationError = serde_json::from_value(json).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn validation_error_implements_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(SearchValidationError::EmptyQuery);
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn validation_error_all_variants_serde() {
        let variants = vec![
            SearchValidationError::EmptyQuery,
            SearchValidationError::QueryTooLong {
                length: 300,
                max: 256,
            },
            SearchValidationError::InvalidLimit { value: 0, max: 50 },
            SearchValidationError::NoSearchTypes,
            SearchValidationError::InvalidOffset { value: 5000 },
        ];
        for v in &variants {
            let json = serde_json::to_value(v).unwrap();
            let back: SearchValidationError = serde_json::from_value(json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // ── Integration / edge-case tests ───────────────────────────────

    #[test]
    fn full_search_workflow() {
        let q = SearchQuery::new("Miles Davis")
            .with_type(SearchType::Album)
            .with_type(SearchType::Artist)
            .with_market("US")
            .with_limit(10);
        assert!(q.validate().is_ok());
        assert_eq!(q.type_string(), "track,album,artist");
    }

    #[test]
    fn search_unicode_query() {
        let q = SearchQuery::new("cafe\u{0301}");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn search_special_characters() {
        let q = SearchQuery::new("rock & roll (live)");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn search_query_with_quotes() {
        let q = SearchQuery::new("\"exact match\"");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn page_with_large_offset() {
        let page: SearchPage<TrackResult> = SearchPage {
            items: vec![],
            total: 10_000,
            limit: 50,
            offset: 950,
            has_next: true,
        };
        assert_eq!(page.next_offset(), Some(1000));
    }

    #[test]
    fn results_with_shows_and_episodes() {
        let r = SearchResults {
            shows: Some(SearchPage {
                items: vec![make_show("s1", "Pod")],
                total: 1,
                ..SearchPage::default()
            }),
            episodes: Some(SearchPage {
                items: vec![make_episode("e1", "Ep")],
                total: 1,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        assert!(r.has_results());
        let types = r.result_types();
        assert!(types.contains(&SearchType::Show));
        assert!(types.contains(&SearchType::Episode));
    }

    #[test]
    fn from_str_empty_string_is_error() {
        assert!("".parse::<SearchType>().is_err());
    }

    #[test]
    fn query_type_string_empty_types() {
        let q = SearchQuery::new("test").with_types(vec![]);
        assert_eq!(q.type_string(), "");
    }

    #[test]
    fn query_type_string_all_types() {
        let q = SearchQuery::new("test").with_types(SearchType::all().to_vec());
        assert_eq!(q.type_string(), "track,album,artist,playlist,show,episode");
    }

    #[test]
    fn page_next_offset_at_boundary() {
        let page: SearchPage<TrackResult> = SearchPage {
            items: vec![],
            total: 20,
            limit: 20,
            offset: 0,
            has_next: false,
        };
        assert_eq!(page.next_offset(), None);
    }

    #[test]
    fn results_has_results_albums_only() {
        let r = SearchResults {
            albums: Some(SearchPage {
                items: vec![make_album("a1", "A")],
                total: 1,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        assert!(r.has_results());
    }

    #[test]
    fn results_has_results_shows_only() {
        let r = SearchResults {
            shows: Some(SearchPage {
                items: vec![make_show("s1", "S")],
                total: 1,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        assert!(r.has_results());
    }

    #[test]
    fn results_has_results_episodes_only() {
        let r = SearchResults {
            episodes: Some(SearchPage {
                items: vec![make_episode("e1", "E")],
                total: 1,
                ..SearchPage::default()
            }),
            ..SearchResults::default()
        };
        assert!(r.has_results());
    }

    #[test]
    fn validator_accepts_boundary_query_length() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("x".repeat(256));
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validator_accepts_boundary_limit() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("test").with_limit(1);
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validator_accepts_zero_offset() {
        let v = SearchValidator::default();
        let q = SearchQuery::new("test").with_offset(0);
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validator_validation_order_empty_before_long() {
        let v = SearchValidator::default();
        let q = SearchQuery {
            query: String::new(),
            search_types: vec![SearchType::Track],
            market: None,
            limit: 20,
            offset: 0,
            include_external: None,
        };
        assert_eq!(
            v.validate_query(&q).unwrap_err(),
            SearchValidationError::EmptyQuery
        );
    }

    // ── Additional edge cases for full coverage ─────────────────────

    #[test]
    fn search_type_from_str_podcast_uppercase() {
        assert_eq!("PODCAST".parse::<SearchType>().unwrap(), SearchType::Show);
    }

    #[test]
    fn search_type_from_str_mixed_case_podcast() {
        assert_eq!("Podcast".parse::<SearchType>().unwrap(), SearchType::Show);
    }

    #[test]
    fn results_total_with_none_types() {
        let r = SearchResults {
            tracks: None,
            albums: None,
            artists: None,
            playlists: None,
            shows: None,
            episodes: None,
        };
        assert_eq!(r.total_results(), 0);
    }

    #[test]
    fn page_serde_album_roundtrip() {
        let page = SearchPage {
            items: vec![make_album("a1", "Album")],
            total: 10,
            limit: 5,
            offset: 0,
            has_next: true,
        };
        let json = serde_json::to_value(&page).unwrap();
        let back: SearchPage<AlbumResult> = serde_json::from_value(json).unwrap();
        assert_eq!(back.items[0].name, "Album");
    }

    #[test]
    fn page_serde_artist_roundtrip() {
        let page = SearchPage {
            items: vec![make_artist("ar1", "Artist")],
            total: 5,
            limit: 10,
            offset: 0,
            has_next: false,
        };
        let json = serde_json::to_value(&page).unwrap();
        let back: SearchPage<ArtistResult> = serde_json::from_value(json).unwrap();
        assert_eq!(back.items[0].name, "Artist");
    }

    #[test]
    fn page_serde_playlist_roundtrip() {
        let page = SearchPage {
            items: vec![make_playlist("p1", "Playlist")],
            total: 1,
            limit: 20,
            offset: 0,
            has_next: false,
        };
        let json = serde_json::to_value(&page).unwrap();
        let back: SearchPage<PlaylistResult> = serde_json::from_value(json).unwrap();
        assert_eq!(back.items[0].name, "Playlist");
    }

    #[test]
    fn page_serde_show_roundtrip() {
        let page = SearchPage {
            items: vec![make_show("s1", "Show")],
            total: 1,
            limit: 20,
            offset: 0,
            has_next: false,
        };
        let json = serde_json::to_value(&page).unwrap();
        let back: SearchPage<ShowResult> = serde_json::from_value(json).unwrap();
        assert_eq!(back.items[0].name, "Show");
    }

    #[test]
    fn page_serde_episode_roundtrip() {
        let page = SearchPage {
            items: vec![make_episode("e1", "Episode")],
            total: 1,
            limit: 20,
            offset: 0,
            has_next: false,
        };
        let json = serde_json::to_value(&page).unwrap();
        let back: SearchPage<EpisodeResult> = serde_json::from_value(json).unwrap();
        assert_eq!(back.items[0].name, "Episode");
    }

    #[test]
    fn query_with_type_adds_multiple_distinct() {
        let q = SearchQuery::new("test")
            .with_type(SearchType::Album)
            .with_type(SearchType::Artist)
            .with_type(SearchType::Show);
        assert_eq!(q.search_types.len(), 4);
    }

    #[test]
    fn query_with_type_no_duplicate_show() {
        let q = SearchQuery::new("test")
            .with_types(vec![SearchType::Show])
            .with_type(SearchType::Show);
        assert_eq!(q.search_types.len(), 1);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    fn make_track(id: &str, name: &str) -> TrackResult {
        TrackResult {
            id: id.into(),
            name: name.into(),
            artists: vec!["Miles Davis".into()],
            album_name: Some("Album".into()),
            duration_ms: 345_000,
            explicit: false,
            popularity: Some(85),
            uri: format!("spotify:track:{id}"),
        }
    }

    fn make_album(id: &str, name: &str) -> AlbumResult {
        AlbumResult {
            id: id.into(),
            name: name.into(),
            artists: vec!["Miles Davis".into()],
            release_date: Some("1959-08-17".into()),
            total_tracks: 5,
            album_type: Some("album".into()),
            uri: format!("spotify:album:{id}"),
        }
    }

    fn make_artist(id: &str, name: &str) -> ArtistResult {
        ArtistResult {
            id: id.into(),
            name: name.into(),
            genres: vec!["jazz".into()],
            popularity: Some(78),
            followers: Some(5_000_000),
            uri: format!("spotify:artist:{id}"),
        }
    }

    fn make_playlist(id: &str, name: &str) -> PlaylistResult {
        PlaylistResult {
            id: id.into(),
            name: name.into(),
            owner: Some("DJ Cool".into()),
            track_count: Some(42),
            public: Some(true),
            uri: format!("spotify:playlist:{id}"),
        }
    }

    fn make_show(id: &str, name: &str) -> ShowResult {
        ShowResult {
            id: id.into(),
            name: name.into(),
            publisher: Some("Publisher Co".into()),
            total_episodes: Some(100),
            uri: format!("spotify:show:{id}"),
        }
    }

    fn make_episode(id: &str, name: &str) -> EpisodeResult {
        EpisodeResult {
            id: id.into(),
            name: name.into(),
            show_name: Some("Parent Show".into()),
            duration_ms: 1_800_000,
            release_date: Some("2024-06-01".into()),
            uri: format!("spotify:episode:{id}"),
        }
    }
}
