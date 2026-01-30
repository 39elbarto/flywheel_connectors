//! Twitter connector configuration.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration for the Twitter connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwitterConfig {
    /// OAuth 1.0a Consumer Key (API Key)
    pub consumer_key: String,

    /// OAuth 1.0a Consumer Secret (API Secret)
    pub consumer_secret: String,

    /// OAuth 1.0a Access Token
    pub access_token: String,

    /// OAuth 1.0a Access Token Secret
    pub access_token_secret: String,

    /// OAuth 2.0 Bearer Token (for app-only auth)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,

    /// Base URL for the Twitter API v2 (default: <https://api.twitter.com>)
    #[serde(default = "default_api_url")]
    pub api_url: String,

    /// Upload URL for media (default: <https://upload.twitter.com>)
    #[serde(default = "default_upload_url")]
    pub upload_url: String,

    /// Stream URL for filtered stream (default: <https://stream.twitter.com>)
    #[serde(default = "default_stream_url")]
    pub stream_url: String,

    /// Request timeout
    #[serde(default = "default_timeout", with = "duration_secs")]
    pub timeout: Duration,

    /// Retry configuration
    #[serde(default)]
    pub retry: RetryConfig,
}

fn default_api_url() -> String {
    "https://api.twitter.com".into()
}

fn default_upload_url() -> String {
    "https://upload.twitter.com".into()
}

fn default_stream_url() -> String {
    "https://api.twitter.com".into()
}

const fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

mod duration_secs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Retry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Initial delay between retries in milliseconds
    #[serde(default = "default_initial_delay_ms")]
    pub initial_delay_ms: u64,

    /// Maximum delay between retries in milliseconds
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,

    /// Jitter factor (0.0-1.0)
    #[serde(default = "default_jitter")]
    pub jitter: f64,
}

const fn default_max_attempts() -> u32 {
    3
}

const fn default_initial_delay_ms() -> u64 {
    1000
}

const fn default_max_delay_ms() -> u64 {
    60_000
}

const fn default_jitter() -> f64 {
    0.1
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_delay_ms: default_initial_delay_ms(),
            max_delay_ms: default_max_delay_ms(),
            jitter: default_jitter(),
        }
    }
}

impl Default for TwitterConfig {
    fn default() -> Self {
        Self {
            consumer_key: String::new(),
            consumer_secret: String::new(),
            access_token: String::new(),
            access_token_secret: String::new(),
            bearer_token: None,
            api_url: default_api_url(),
            upload_url: default_upload_url(),
            stream_url: default_stream_url(),
            timeout: default_timeout(),
            retry: RetryConfig::default(),
        }
    }
}

/// Rate limit information from Twitter API headers.
#[derive(Debug, Clone, Default)]
pub struct RateLimitInfo {
    /// Maximum number of requests allowed in the window
    pub limit: Option<u32>,

    /// Remaining requests in the current window
    pub remaining: Option<u32>,

    /// Unix timestamp when the rate limit resets
    pub reset: Option<u64>,
}

impl RateLimitInfo {
    /// Parse rate limit info from response headers.
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Self {
        Self {
            limit: headers
                .get("x-rate-limit-limit")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
            remaining: headers
                .get("x-rate-limit-remaining")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
            reset: headers
                .get("x-rate-limit-reset")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
        }
    }

    /// Check if we're rate limited (remaining == 0).
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.remaining == Some(0)
    }

    /// Get the duration until rate limit resets.
    #[must_use]
    pub fn time_until_reset(&self) -> Option<Duration> {
        let reset = self.reset?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();

        if reset > now {
            Some(Duration::from_secs(reset - now))
        } else {
            None
        }
    }
}
