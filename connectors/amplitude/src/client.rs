//! `Amplitude` API client.

use std::fmt;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{AmplitudeError, AmplitudeResult},
    types::ApiErrorResponse,
};

/// Default `Amplitude` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://amplitude.com/api/2";

/// `Amplitude` authentication credentials.
#[derive(Clone)]
pub struct AmplitudeAuth {
    pub api_key: String,
    pub secret_key: String,
}

impl AmplitudeAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        let prefix = if self.api_key.len() >= 4 {
            &self.api_key[..4]
        } else {
            &self.api_key
        };
        format!("api_key:{prefix}...,secret_key:redacted")
    }

    /// Build the Basic auth header value.
    #[must_use]
    pub fn basic_auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.api_key, self.secret_key);
        format!("Basic {}", BASE64.encode(credentials.as_bytes()))
    }
}

impl fmt::Debug for AmplitudeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AmplitudeAuth")
            .field("api_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

/// `Amplitude` API client.
pub struct AmplitudeClient {
    client: Client,
    auth: AmplitudeAuth,
    base_url: String,
}

impl fmt::Debug for AmplitudeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AmplitudeClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl AmplitudeClient {
    /// Create a new `Amplitude` client.
    pub fn new(auth: AmplitudeAuth, base_url: Option<&str>) -> AmplitudeResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-amplitude/0.1.0 (FCP connector)")
            .build()?;

        let url = match base_url {
            Some(u) => u.trim_end_matches('/').to_string(),
            None => DEFAULT_BASE_URL.to_string(),
        };

        Ok(Self {
            client,
            auth,
            base_url: url,
        })
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("Authorization", self.auth.basic_auth_header())
    }

    async fn handle_response(&self, resp: Response) -> AmplitudeResult<serde_json::Value> {
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
    ) -> AmplitudeResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error.or(e.message))
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(AmplitudeError::Unauthorized),
            403 => Err(AmplitudeError::Forbidden),
            404 => Err(AmplitudeError::NotFound { resource: detail }),
            429 => Err(AmplitudeError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(AmplitudeError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> AmplitudeResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Charts --

    /// Query a chart by ID.
    pub async fn query_chart(&self, chart_id: &str) -> AmplitudeResult<serde_json::Value> {
        self.get(&format!("/charts/{chart_id}/query")).await
    }

    // -- Cohorts --

    /// List all cohorts.
    pub async fn list_cohorts(&self) -> AmplitudeResult<serde_json::Value> {
        self.get("/cohorts").await
    }

    // -- Events --

    /// Export events for a date range.
    pub async fn export_events(
        &self,
        start: &str,
        end: &str,
    ) -> AmplitudeResult<serde_json::Value> {
        self.get(&format!("/export?start={start}&end={end}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_keys() {
        let auth = AmplitudeAuth {
            api_key: "my-api-key-123".into(),
            secret_key: "super-secret-key".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("my-api-key-123"));
        assert!(!dbg.contains("super-secret-key"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_redacted_label() {
        let auth = AmplitudeAuth {
            api_key: "abcdef123456".into(),
            secret_key: "my_super_secret_value".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("abcd"));
        assert!(label.contains("redacted"));
        assert!(!label.contains("my_super_secret_value"));
        assert!(!label.contains("abcdef123456"));
    }

    #[test]
    fn auth_redacted_label_short_key() {
        let auth = AmplitudeAuth {
            api_key: "ab".into(),
            secret_key: "sec".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("ab"));
        assert!(label.contains("redacted"));
    }

    #[test]
    fn auth_basic_auth_header() {
        let auth = AmplitudeAuth {
            api_key: "api_key".into(),
            secret_key: "secret_key".into(),
        };
        let header = auth.basic_auth_header();
        assert!(header.starts_with("Basic "));
        let encoded = &header["Basic ".len()..];
        let decoded = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, "api_key:secret_key");
    }

    #[test]
    fn auth_basic_auth_header_special_chars() {
        let auth = AmplitudeAuth {
            api_key: "key+with/special=chars".into(),
            secret_key: "sec:ret!@#".into(),
        };
        let header = auth.basic_auth_header();
        assert!(header.starts_with("Basic "));
        let encoded = &header["Basic ".len()..];
        let decoded = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, "key+with/special=chars:sec:ret!@#");
    }

    #[test]
    fn auth_basic_auth_header_empty_values() {
        let auth = AmplitudeAuth {
            api_key: String::new(),
            secret_key: String::new(),
        };
        let header = auth.basic_auth_header();
        let encoded = &header["Basic ".len()..];
        let decoded = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, ":");
    }

    #[test]
    fn client_new_with_custom_base_url() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let client = AmplitudeClient::new(auth, Some("https://test.example.com/api")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_new_default_url() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let client = AmplitudeClient::new(auth, None).unwrap();
        assert_eq!(client.base_url, "https://amplitude.com/api/2");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let client =
            AmplitudeClient::new(auth, Some("https://test.example.com/api/")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let client = AmplitudeClient::new(auth, Some("https://example.com")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
        assert!(!dbg.contains("KEY"));
        assert!(!dbg.contains("SECRET"));
    }

    #[test]
    fn auth_clone() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let cloned = AmplitudeAuth::clone(&auth);
        assert_eq!(cloned.api_key, "KEY");
        assert_eq!(cloned.secret_key, "SECRET");
    }

    #[test]
    fn default_base_url_constant() {
        assert_eq!(DEFAULT_BASE_URL, "https://amplitude.com/api/2");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let auth = AmplitudeAuth {
            api_key: "K".into(),
            secret_key: "S".into(),
        };
        let client =
            AmplitudeClient::new(auth, Some("https://example.com///")).unwrap();
        // trim_end_matches removes all trailing slashes
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn auth_basic_auth_header_consistency() {
        let auth = AmplitudeAuth {
            api_key: "test_key".into(),
            secret_key: "test_secret".into(),
        };
        // Calling twice should produce the same result
        let h1 = auth.basic_auth_header();
        let h2 = auth.basic_auth_header();
        assert_eq!(h1, h2);
    }
}
