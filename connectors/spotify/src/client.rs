//! `Spotify` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SpotifyError, SpotifyResult},
    types::ApiErrorResponse,
};

/// Default `Spotify` Web API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.spotify.com/v1";

/// Authentication mode for the `Spotify` API.
#[derive(Clone)]
pub enum SpotifyAuth {
    /// `OAuth2` access token (passed as `Authorization: Bearer <token>`).
    AccessToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl SpotifyAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::AccessToken(_) => "access_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for SpotifyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessToken(_) => f.debug_tuple("AccessToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Spotify` API client.
pub struct SpotifyClient {
    client: Client,
    auth: SpotifyAuth,
    base_url: String,
}

impl fmt::Debug for SpotifyClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpotifyClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl SpotifyClient {
    /// Create a new `Spotify` client.
    pub fn new(auth: SpotifyAuth, base_url: Option<&str>) -> SpotifyResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-spotify/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            SpotifyAuth::AccessToken(token) => req.bearer_auth(token),
            SpotifyAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> SpotifyResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> SpotifyResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Spotify returns {"error": {"status": 401, "message": "..."}} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .and_then(|e| e.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(SpotifyError::Unauthorized),
            403 => Err(SpotifyError::Forbidden),
            404 => Err(SpotifyError::NotFound { resource: detail }),
            429 => Err(SpotifyError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SpotifyError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> SpotifyResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Profile --

    /// Get the current user's profile.
    pub async fn get_current_profile(&self) -> SpotifyResult<serde_json::Value> {
        self.get("/me").await
    }

    // -- Search --

    /// Search for tracks, albums, artists, playlists, etc.
    pub async fn search(
        &self,
        query: &str,
        types: &str,
        limit: u32,
    ) -> SpotifyResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        self.get(&format!(
            "/search?q={encoded_query}&type={types}&limit={limit}"
        ))
        .await
    }

    // -- Tracks --

    /// Get a track by ID.
    pub async fn get_track(&self, track_id: &str) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/tracks/{track_id}")).await
    }

    // -- Albums --

    /// Get an album by ID.
    pub async fn get_album(&self, album_id: &str) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/albums/{album_id}")).await
    }

    // -- Artists --

    /// Get an artist by ID.
    pub async fn get_artist(&self, artist_id: &str) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/artists/{artist_id}")).await
    }

    // -- Playlists --

    /// Get a playlist by ID.
    pub async fn get_playlist(&self, playlist_id: &str) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/playlists/{playlist_id}")).await
    }

    /// List the current user's playlists.
    pub async fn list_playlists(&self) -> SpotifyResult<serde_json::Value> {
        self.get("/me/playlists").await
    }

    // -- Player --

    /// Get the current user's recently played tracks.
    pub async fn get_recently_played(&self, limit: u32) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/me/player/recently-played?limit={limit}"))
            .await
    }

    // -- Top Items --

    /// Get the current user's top artists or tracks.
    pub async fn get_top_items(
        &self,
        item_type: &str,
        time_range: &str,
        limit: u32,
    ) -> SpotifyResult<serde_json::Value> {
        self.get(&format!(
            "/me/top/{item_type}?time_range={time_range}&limit={limit}"
        ))
        .await
    }

    // -- Recommendations --

    /// Get track recommendations based on seed artists and genres.
    pub async fn get_recommendations(
        &self,
        seed_artists: &str,
        seed_genres: &str,
        limit: u32,
    ) -> SpotifyResult<serde_json::Value> {
        self.get(&format!(
            "/recommendations?seed_artists={seed_artists}&seed_genres={seed_genres}&limit={limit}"
        ))
        .await
    }
}

/// Simple percent-encoding for query strings.
fn percent_encode(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('+', "%2B")
        .replace('#', "%23")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = SpotifyAuth::AccessToken("secret-access-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-access-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = SpotifyAuth::AccessToken("tok".into());
        assert!(!token.is_secretless());
        let cred = SpotifyAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = SpotifyAuth::AccessToken("tok".into());
        assert_eq!(token.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = SpotifyAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = SpotifyClient::new(SpotifyAuth::AccessToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SpotifyClient::new(
            SpotifyAuth::AccessToken("tok".into()),
            Some("https://test.example.com/v1/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/v1");
    }

    #[test]
    fn client_debug_redacts() {
        let client = SpotifyClient::new(SpotifyAuth::AccessToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn percent_encode_spaces() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn percent_encode_special_chars() {
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn percent_encode_hash() {
        assert_eq!(percent_encode("test#1"), "test%231");
    }

    #[test]
    fn percent_encode_plus() {
        assert_eq!(percent_encode("a+b"), "a%2Bb");
    }

    #[test]
    fn percent_encode_percent() {
        assert_eq!(percent_encode("100%"), "100%25");
    }

    #[test]
    fn percent_encode_no_change() {
        assert_eq!(percent_encode("simple"), "simple");
    }

    // ── Additional client coverage ───────────────────────────────

    #[test]
    fn auth_debug_credential_id() {
        let cred = SpotifyAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone() {
        let auth = SpotifyAuth::AccessToken("secret".into());
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert_eq!(auth2.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn auth_credential_id_clone() {
        let id = CredentialId::new();
        let auth = SpotifyAuth::CredentialId(id);
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert!(auth2.is_secretless());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = SpotifyClient::new(SpotifyAuth::AccessToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("SpotifyClient"));
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_custom_url_trimmed() {
        let client = SpotifyClient::new(
            SpotifyAuth::AccessToken("tok".into()),
            Some("https://api.example.com/v1///"),
        )
        .unwrap();
        // Only trailing slashes should be stripped
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn default_base_url_constant() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.spotify.com/v1");
    }

    #[test]
    fn percent_encode_empty_string() {
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn percent_encode_all_special() {
        let result = percent_encode("% & = + #");
        assert!(result.contains("%25"));
        assert!(result.contains("%26"));
        assert!(result.contains("%3D"));
        assert!(result.contains("%2B"));
        assert!(result.contains("%23"));
    }

    #[test]
    fn percent_encode_unicode_untouched() {
        // Non-special ASCII chars pass through
        let result = percent_encode("abc123");
        assert_eq!(result, "abc123");
    }

    #[test]
    fn client_with_credential_id_auth() {
        let client =
            SpotifyClient::new(SpotifyAuth::CredentialId(CredentialId::new()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn percent_encode_multiple_spaces() {
        let result = percent_encode("a b c d");
        assert_eq!(result, "a%20b%20c%20d");
    }

    #[test]
    fn percent_encode_consecutive_specials() {
        let result = percent_encode("&&==");
        assert_eq!(result, "%26%26%3D%3D");
    }
}
