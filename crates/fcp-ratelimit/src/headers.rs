//! Rate limit header parsing for various providers.
//!
//! Parses standard and provider-specific rate limit headers.

use std::collections::HashMap;
use std::time::Duration;

/// Parsed rate limit information from HTTP headers.
#[derive(Debug, Clone, Default)]
pub struct RateLimitHeaders {
    /// Maximum requests allowed.
    pub limit: Option<u32>,

    /// Remaining requests in current window.
    pub remaining: Option<u32>,

    /// Seconds until reset.
    pub reset_seconds: Option<u64>,

    /// Unix timestamp of reset.
    pub reset_at: Option<u64>,

    /// Retry after duration (from 429 response).
    pub retry_after: Option<Duration>,

    /// Provider-specific additional info.
    pub provider_info: HashMap<String, String>,
}

impl RateLimitHeaders {
    /// Create empty headers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse headers from a header map.
    #[must_use]
    pub fn parse(headers: &HashMap<String, String>) -> Self {
        let mut result = Self::new();

        // Standard headers
        result.limit = parse_header_u32(headers, "x-ratelimit-limit")
            .or_else(|| parse_header_u32(headers, "x-rate-limit-limit"))
            .or_else(|| parse_header_u32(headers, "ratelimit-limit"));

        result.remaining = parse_header_u32(headers, "x-ratelimit-remaining")
            .or_else(|| parse_header_u32(headers, "x-rate-limit-remaining"))
            .or_else(|| parse_header_u32(headers, "ratelimit-remaining"));

        result.reset_seconds = parse_header_u64(headers, "x-ratelimit-reset")
            .or_else(|| parse_header_u64(headers, "x-rate-limit-reset"))
            .or_else(|| parse_header_u64(headers, "ratelimit-reset"));

        // Retry-After header
        if let Some(retry) = headers.get("retry-after") {
            if let Ok(secs) = retry.parse::<u64>() {
                result.retry_after = Some(Duration::from_secs(secs));
            }
        }

        result
    }

    /// Parse GitHub-specific headers.
    #[must_use]
    pub fn parse_github(headers: &HashMap<String, String>) -> Self {
        let mut result = Self::parse(headers);

        // GitHub uses x-ratelimit-* headers
        if let Some(reset) = parse_header_u64(headers, "x-ratelimit-reset") {
            result.reset_at = Some(reset);
            // Convert epoch timestamp to seconds from now
            if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                let now_secs = now.as_secs();
                if reset > now_secs {
                    result.reset_seconds = Some(reset - now_secs);
                } else {
                    // Reset is in the past; window already expired
                    result.reset_seconds = Some(0);
                }
            }
        }

        // GitHub secondary rate limits
        if let Some(used) = parse_header_u32(headers, "x-ratelimit-used") {
            result
                .provider_info
                .insert("used".to_string(), used.to_string());
        }
        if let Some(resource) = headers.get("x-ratelimit-resource") {
            result
                .provider_info
                .insert("resource".to_string(), resource.clone());
        }

        result
    }

    /// Parse Twitter/X-specific headers.
    #[must_use]
    pub fn parse_twitter(headers: &HashMap<String, String>) -> Self {
        let mut result = Self::parse(headers);

        // Twitter uses x-rate-limit-* headers
        result.limit = result
            .limit
            .or_else(|| parse_header_u32(headers, "x-rate-limit-limit"));
        result.remaining = result
            .remaining
            .or_else(|| parse_header_u32(headers, "x-rate-limit-remaining"));

        if let Some(reset) = parse_header_u64(headers, "x-rate-limit-reset") {
            result.reset_at = Some(reset);
            if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                let now_secs = now.as_secs();
                if reset > now_secs {
                    result.reset_seconds = Some(reset - now_secs);
                } else {
                    // Reset is in the past; window already expired
                    result.reset_seconds = Some(0);
                }
            }
        }

        result
    }

    /// Parse Stripe-specific headers.
    #[must_use]
    pub fn parse_stripe(headers: &HashMap<String, String>) -> Self {
        let mut result = Self::parse(headers);

        // Stripe uses different header naming
        if let Some(request_id) = headers.get("request-id") {
            result
                .provider_info
                .insert("request_id".to_string(), request_id.clone());
        }

        result
    }

    /// Parse OpenAI-specific headers.
    #[must_use]
    pub fn parse_openai(headers: &HashMap<String, String>) -> Self {
        let mut result = Self::parse(headers);

        // OpenAI has specific rate limit headers
        if let Some(limit_requests) = parse_header_u32(headers, "x-ratelimit-limit-requests") {
            result.limit = Some(limit_requests);
        }
        if let Some(remaining_requests) =
            parse_header_u32(headers, "x-ratelimit-remaining-requests")
        {
            result.remaining = Some(remaining_requests);
        }

        // Token limits (for LLM APIs)
        if let Some(limit_tokens) = parse_header_u32(headers, "x-ratelimit-limit-tokens") {
            result
                .provider_info
                .insert("limit_tokens".to_string(), limit_tokens.to_string());
        }
        if let Some(remaining_tokens) = parse_header_u32(headers, "x-ratelimit-remaining-tokens") {
            result
                .provider_info
                .insert("remaining_tokens".to_string(), remaining_tokens.to_string());
        }

        // Reset times
        if let Some(reset_requests) = headers.get("x-ratelimit-reset-requests") {
            if let Some(duration) = parse_duration_string(reset_requests) {
                result.reset_seconds = Some(duration.as_secs());
            }
        }

        result
    }

    /// Parse Anthropic-specific headers.
    #[must_use]
    pub fn parse_anthropic(headers: &HashMap<String, String>) -> Self {
        let mut result = Self::parse(headers);

        // Anthropic uses similar headers to OpenAI
        if let Some(limit_requests) =
            parse_header_u32(headers, "anthropic-ratelimit-requests-limit")
        {
            result.limit = Some(limit_requests);
        }
        if let Some(remaining_requests) =
            parse_header_u32(headers, "anthropic-ratelimit-requests-remaining")
        {
            result.remaining = Some(remaining_requests);
        }

        // Token limits
        if let Some(limit_tokens) = parse_header_u32(headers, "anthropic-ratelimit-tokens-limit") {
            result
                .provider_info
                .insert("limit_tokens".to_string(), limit_tokens.to_string());
        }
        if let Some(remaining_tokens) =
            parse_header_u32(headers, "anthropic-ratelimit-tokens-remaining")
        {
            result
                .provider_info
                .insert("remaining_tokens".to_string(), remaining_tokens.to_string());
        }

        // Reset time
        if let Some(reset) = headers.get("anthropic-ratelimit-requests-reset") {
            result
                .provider_info
                .insert("reset_time".to_string(), reset.clone());
        }

        result
    }

    /// Get the suggested wait time from headers.
    #[must_use]
    pub const fn suggested_wait(&self) -> Option<Duration> {
        // Prefer retry_after if present
        if let Some(retry) = self.retry_after {
            return Some(retry);
        }

        // Fall back to reset_seconds
        if let Some(secs) = self.reset_seconds {
            return Some(Duration::from_secs(secs));
        }

        None
    }

    /// Check if rate limited.
    #[must_use]
    pub fn is_limited(&self) -> bool {
        self.remaining == Some(0) || self.retry_after.is_some()
    }
}

/// Helper to parse a header as u32.
fn parse_header_u32(headers: &HashMap<String, String>, key: &str) -> Option<u32> {
    headers.get(key).and_then(|v| v.parse().ok())
}

/// Helper to parse a header as u64.
fn parse_header_u64(headers: &HashMap<String, String>, key: &str) -> Option<u64> {
    headers.get(key).and_then(|v| v.parse().ok())
}

/// Parse duration strings like "1s", "500ms", "5m", "2h".
fn parse_duration_string(s: &str) -> Option<Duration> {
    let s = s.trim();

    // Try simple seconds
    if let Ok(secs) = s.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }

    // Try with suffix
    if s.ends_with("ms") {
        if let Ok(ms) = s.trim_end_matches("ms").parse::<u64>() {
            return Some(Duration::from_millis(ms));
        }
    }
    if s.ends_with('s') && !s.ends_with("ms") {
        if let Ok(secs) = s.trim_end_matches('s').parse::<f64>() {
            return Some(Duration::from_secs_f64(secs));
        }
    }
    if s.ends_with('m') {
        if let Ok(mins) = s.trim_end_matches('m').parse::<u64>() {
            return Some(Duration::from_secs(mins * 60));
        }
    }
    if s.ends_with('h') {
        if let Ok(hours) = s.trim_end_matches('h').parse::<u64>() {
            return Some(Duration::from_secs(hours * 3600));
        }
    }

    None
}

/// Provider type for automatic header parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// Standard rate limit headers.
    Standard,
    /// GitHub API.
    GitHub,
    /// Twitter/X API.
    Twitter,
    /// Stripe API.
    Stripe,
    /// `OpenAI` API.
    OpenAI,
    /// Anthropic API.
    Anthropic,
}

impl Provider {
    /// Parse headers for this provider.
    #[must_use]
    pub fn parse_headers(&self, headers: &HashMap<String, String>) -> RateLimitHeaders {
        match self {
            Self::Standard => RateLimitHeaders::parse(headers),
            Self::GitHub => RateLimitHeaders::parse_github(headers),
            Self::Twitter => RateLimitHeaders::parse_twitter(headers),
            Self::Stripe => RateLimitHeaders::parse_stripe(headers),
            Self::OpenAI => RateLimitHeaders::parse_openai(headers),
            Self::Anthropic => RateLimitHeaders::parse_anthropic(headers),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Standard header parsing ─────────────────────────────────────────

    #[test]
    fn test_parse_standard_headers() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "100".to_string());
        headers.insert("x-ratelimit-remaining".to_string(), "50".to_string());
        headers.insert("x-ratelimit-reset".to_string(), "60".to_string());

        let parsed = RateLimitHeaders::parse(&headers);

        assert_eq!(parsed.limit, Some(100));
        assert_eq!(parsed.remaining, Some(50));
        assert_eq!(parsed.reset_seconds, Some(60));
        assert!(!parsed.is_limited());
    }

    #[test]
    fn parse_standard_hyphenated_variant() {
        let mut headers = HashMap::new();
        headers.insert("x-rate-limit-limit".to_string(), "200".to_string());
        headers.insert("x-rate-limit-remaining".to_string(), "100".to_string());
        headers.insert("x-rate-limit-reset".to_string(), "120".to_string());

        let parsed = RateLimitHeaders::parse(&headers);
        assert_eq!(parsed.limit, Some(200));
        assert_eq!(parsed.remaining, Some(100));
    }

    #[test]
    fn parse_standard_ratelimit_prefix() {
        let mut headers = HashMap::new();
        headers.insert("ratelimit-limit".to_string(), "50".to_string());
        headers.insert("ratelimit-remaining".to_string(), "25".to_string());
        headers.insert("ratelimit-reset".to_string(), "30".to_string());

        let parsed = RateLimitHeaders::parse(&headers);
        assert_eq!(parsed.limit, Some(50));
        assert_eq!(parsed.remaining, Some(25));
        assert_eq!(parsed.reset_seconds, Some(30));
    }

    #[test]
    fn parse_empty_headers() {
        let headers = HashMap::new();
        let parsed = RateLimitHeaders::parse(&headers);
        assert!(parsed.limit.is_none());
        assert!(parsed.remaining.is_none());
        assert!(parsed.reset_seconds.is_none());
        assert!(parsed.retry_after.is_none());
        assert!(!parsed.is_limited());
    }

    #[test]
    fn parse_malformed_header_values() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "not_a_number".to_string());
        headers.insert("x-ratelimit-remaining".to_string(), "-5".to_string());
        headers.insert("retry-after".to_string(), "abc".to_string());

        let parsed = RateLimitHeaders::parse(&headers);
        assert!(parsed.limit.is_none());
        assert!(parsed.remaining.is_none());
        assert!(parsed.retry_after.is_none());
    }

    #[test]
    fn test_parse_retry_after() {
        let mut headers = HashMap::new();
        headers.insert("retry-after".to_string(), "30".to_string());

        let parsed = RateLimitHeaders::parse(&headers);

        assert_eq!(parsed.retry_after, Some(Duration::from_secs(30)));
        assert!(parsed.is_limited());
    }

    #[test]
    fn is_limited_with_zero_remaining() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-remaining".to_string(), "0".to_string());

        let parsed = RateLimitHeaders::parse(&headers);
        assert!(parsed.is_limited());
    }

    #[test]
    fn is_limited_with_nonzero_remaining_no_retry() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-remaining".to_string(), "5".to_string());

        let parsed = RateLimitHeaders::parse(&headers);
        assert!(!parsed.is_limited());
    }

    // ── GitHub header parsing ───────────────────────────────────────────

    #[test]
    fn parse_github_headers() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "5000".to_string());
        headers.insert("x-ratelimit-remaining".to_string(), "4999".to_string());
        headers.insert("x-ratelimit-used".to_string(), "1".to_string());
        headers.insert("x-ratelimit-resource".to_string(), "core".to_string());

        let parsed = RateLimitHeaders::parse_github(&headers);
        assert_eq!(parsed.limit, Some(5000));
        assert_eq!(parsed.remaining, Some(4999));
        assert_eq!(parsed.provider_info.get("used"), Some(&"1".to_string()));
        assert_eq!(
            parsed.provider_info.get("resource"),
            Some(&"core".to_string())
        );
    }

    #[test]
    fn parse_github_reset_as_timestamp() {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let reset_at = now_secs + 120;

        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "5000".to_string());
        headers.insert("x-ratelimit-remaining".to_string(), "4000".to_string());
        headers.insert("x-ratelimit-reset".to_string(), reset_at.to_string());

        let parsed = RateLimitHeaders::parse_github(&headers);
        assert_eq!(parsed.reset_at, Some(reset_at));
        // reset_seconds should be approximately 120
        if let Some(secs) = parsed.reset_seconds {
            assert!(secs <= 121, "reset_seconds={secs} too large");
            assert!(secs >= 118, "reset_seconds={secs} too small");
        }
    }

    #[test]
    fn parse_github_reset_in_past() {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let reset_at = now_secs.saturating_sub(100);

        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-reset".to_string(), reset_at.to_string());

        let parsed = RateLimitHeaders::parse_github(&headers);
        assert_eq!(parsed.reset_at, Some(reset_at));
        // Reset is in the past, so reset_seconds should be 0
        assert_eq!(parsed.reset_seconds, Some(0));
    }

    // ── Twitter header parsing ──────────────────────────────────────────

    #[test]
    fn parse_twitter_headers() {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let reset_at = now_secs + 60;

        let mut headers = HashMap::new();
        headers.insert("x-rate-limit-limit".to_string(), "900".to_string());
        headers.insert("x-rate-limit-remaining".to_string(), "899".to_string());
        headers.insert("x-rate-limit-reset".to_string(), reset_at.to_string());

        let parsed = RateLimitHeaders::parse_twitter(&headers);
        assert_eq!(parsed.limit, Some(900));
        assert_eq!(parsed.remaining, Some(899));
        assert_eq!(parsed.reset_at, Some(reset_at));
    }

    #[test]
    fn parse_twitter_empty_headers() {
        let headers = HashMap::new();
        let parsed = RateLimitHeaders::parse_twitter(&headers);
        assert!(parsed.limit.is_none());
        assert!(parsed.remaining.is_none());
    }

    // ── Stripe header parsing ───────────────────────────────────────────

    #[test]
    fn parse_stripe_headers() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "100".to_string());
        headers.insert("x-ratelimit-remaining".to_string(), "99".to_string());
        headers.insert("request-id".to_string(), "req_abc123".to_string());

        let parsed = RateLimitHeaders::parse_stripe(&headers);
        assert_eq!(parsed.limit, Some(100));
        assert_eq!(parsed.remaining, Some(99));
        assert_eq!(
            parsed.provider_info.get("request_id"),
            Some(&"req_abc123".to_string())
        );
    }

    #[test]
    fn parse_stripe_no_request_id() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "25".to_string());

        let parsed = RateLimitHeaders::parse_stripe(&headers);
        assert_eq!(parsed.limit, Some(25));
        assert!(!parsed.provider_info.contains_key("request_id"));
    }

    // ── OpenAI header parsing ───────────────────────────────────────────

    #[test]
    fn test_parse_openai_headers() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit-requests".to_string(), "60".to_string());
        headers.insert(
            "x-ratelimit-remaining-requests".to_string(),
            "59".to_string(),
        );
        headers.insert("x-ratelimit-limit-tokens".to_string(), "150000".to_string());
        headers.insert(
            "x-ratelimit-remaining-tokens".to_string(),
            "149000".to_string(),
        );

        let parsed = RateLimitHeaders::parse_openai(&headers);

        assert_eq!(parsed.limit, Some(60));
        assert_eq!(parsed.remaining, Some(59));
        assert_eq!(
            parsed.provider_info.get("limit_tokens"),
            Some(&"150000".to_string())
        );
    }

    #[test]
    fn parse_openai_reset_requests_duration() {
        let mut headers = HashMap::new();
        headers.insert(
            "x-ratelimit-reset-requests".to_string(),
            "500ms".to_string(),
        );

        let parsed = RateLimitHeaders::parse_openai(&headers);
        assert_eq!(parsed.reset_seconds, Some(0)); // 500ms rounds to 0 seconds
    }

    #[test]
    fn parse_openai_all_token_info() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit-tokens".to_string(), "200000".to_string());
        headers.insert(
            "x-ratelimit-remaining-tokens".to_string(),
            "180000".to_string(),
        );
        headers.insert("x-ratelimit-limit-requests".to_string(), "3500".to_string());
        headers.insert(
            "x-ratelimit-remaining-requests".to_string(),
            "3499".to_string(),
        );
        headers.insert("x-ratelimit-reset-requests".to_string(), "17ms".to_string());

        let parsed = RateLimitHeaders::parse_openai(&headers);
        assert_eq!(parsed.limit, Some(3500));
        assert_eq!(parsed.remaining, Some(3499));
        assert_eq!(
            parsed.provider_info.get("limit_tokens"),
            Some(&"200000".to_string())
        );
        assert_eq!(
            parsed.provider_info.get("remaining_tokens"),
            Some(&"180000".to_string())
        );
    }

    // ── Anthropic header parsing ────────────────────────────────────────

    #[test]
    fn parse_anthropic_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "anthropic-ratelimit-requests-limit".to_string(),
            "1000".to_string(),
        );
        headers.insert(
            "anthropic-ratelimit-requests-remaining".to_string(),
            "999".to_string(),
        );
        headers.insert(
            "anthropic-ratelimit-tokens-limit".to_string(),
            "100000".to_string(),
        );
        headers.insert(
            "anthropic-ratelimit-tokens-remaining".to_string(),
            "99000".to_string(),
        );
        headers.insert(
            "anthropic-ratelimit-requests-reset".to_string(),
            "2026-03-04T00:00:00Z".to_string(),
        );

        let parsed = RateLimitHeaders::parse_anthropic(&headers);
        assert_eq!(parsed.limit, Some(1000));
        assert_eq!(parsed.remaining, Some(999));
        assert_eq!(
            parsed.provider_info.get("limit_tokens"),
            Some(&"100000".to_string())
        );
        assert_eq!(
            parsed.provider_info.get("remaining_tokens"),
            Some(&"99000".to_string())
        );
        assert_eq!(
            parsed.provider_info.get("reset_time"),
            Some(&"2026-03-04T00:00:00Z".to_string())
        );
    }

    #[test]
    fn parse_anthropic_empty() {
        let headers = HashMap::new();
        let parsed = RateLimitHeaders::parse_anthropic(&headers);
        assert!(parsed.limit.is_none());
        assert!(parsed.remaining.is_none());
        assert!(!parsed.provider_info.contains_key("limit_tokens"));
    }

    // ── Provider enum dispatch ──────────────────────────────────────────

    #[test]
    fn provider_parse_headers_dispatch() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "100".to_string());
        headers.insert("x-ratelimit-remaining".to_string(), "50".to_string());

        let standard = Provider::Standard.parse_headers(&headers);
        assert_eq!(standard.limit, Some(100));

        let github = Provider::GitHub.parse_headers(&headers);
        assert_eq!(github.limit, Some(100));

        let twitter = Provider::Twitter.parse_headers(&headers);
        assert_eq!(twitter.limit, Some(100));

        let stripe = Provider::Stripe.parse_headers(&headers);
        assert_eq!(stripe.limit, Some(100));

        let openai = Provider::OpenAI.parse_headers(&headers);
        assert_eq!(openai.limit, Some(100));

        let anthropic = Provider::Anthropic.parse_headers(&headers);
        assert_eq!(anthropic.limit, Some(100));
    }

    #[test]
    fn provider_debug_and_clone_copy_eq() {
        let p = Provider::GitHub;
        let debug = format!("{p:?}");
        assert!(debug.contains("GitHub"));

        let cloned = p;
        assert_eq!(cloned, Provider::GitHub);
        assert_ne!(p, Provider::Twitter);
    }

    // ── Duration string parsing ─────────────────────────────────────────

    #[test]
    fn test_parse_duration_string() {
        assert_eq!(parse_duration_string("30"), Some(Duration::from_secs(30)));
        assert_eq!(
            parse_duration_string("500ms"),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            parse_duration_string("1.5s"),
            Some(Duration::from_secs_f64(1.5))
        );
        assert_eq!(parse_duration_string("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration_string("2h"), Some(Duration::from_secs(7200)));
    }

    #[test]
    fn parse_duration_string_zero() {
        assert_eq!(parse_duration_string("0"), Some(Duration::from_secs(0)));
        assert_eq!(parse_duration_string("0ms"), Some(Duration::from_millis(0)));
        assert_eq!(
            parse_duration_string("0s"),
            Some(Duration::from_secs_f64(0.0))
        );
    }

    #[test]
    fn parse_duration_string_invalid() {
        assert!(parse_duration_string("").is_none());
        assert!(parse_duration_string("abc").is_none());
        assert!(parse_duration_string("xms").is_none());
        assert!(parse_duration_string("??s").is_none());
    }

    #[test]
    fn parse_duration_string_whitespace_trimmed() {
        assert_eq!(
            parse_duration_string("  30  "),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn parse_duration_string_large_values() {
        assert_eq!(
            parse_duration_string("86400"),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(
            parse_duration_string("24h"),
            Some(Duration::from_secs(86400))
        );
    }

    // ── suggested_wait ──────────────────────────────────────────────────

    #[test]
    fn test_suggested_wait() {
        let mut headers = RateLimitHeaders::new();
        headers.retry_after = Some(Duration::from_secs(30));
        headers.reset_seconds = Some(60);

        // Should prefer retry_after
        assert_eq!(headers.suggested_wait(), Some(Duration::from_secs(30)));

        headers.retry_after = None;
        assert_eq!(headers.suggested_wait(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn suggested_wait_none_when_no_info() {
        let headers = RateLimitHeaders::new();
        assert!(headers.suggested_wait().is_none());
    }

    // ── RateLimitHeaders default / new ──────────────────────────────────

    #[test]
    fn rate_limit_headers_default() {
        let headers = RateLimitHeaders::default();
        assert!(headers.limit.is_none());
        assert!(headers.remaining.is_none());
        assert!(headers.reset_seconds.is_none());
        assert!(headers.reset_at.is_none());
        assert!(headers.retry_after.is_none());
        assert!(headers.provider_info.is_empty());
    }

    #[test]
    fn rate_limit_headers_debug_and_clone() {
        let mut headers = RateLimitHeaders::new();
        headers.limit = Some(100);
        headers.remaining = Some(50);

        let cloned = headers.clone();
        assert_eq!(cloned.limit, Some(100));
        assert_eq!(cloned.remaining, Some(50));

        let debug = format!("{headers:?}");
        assert!(debug.contains("RateLimitHeaders"));
    }

    // ── Header priority (x-ratelimit > x-rate-limit > ratelimit) ─────

    #[test]
    fn parse_standard_priority_x_ratelimit_wins() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "100".to_string());
        headers.insert("x-rate-limit-limit".to_string(), "200".to_string());
        headers.insert("ratelimit-limit".to_string(), "300".to_string());

        let parsed = RateLimitHeaders::parse(&headers);
        assert_eq!(parsed.limit, Some(100));
    }

    #[test]
    fn parse_standard_fallback_to_ratelimit_prefix() {
        let mut headers = HashMap::new();
        headers.insert("ratelimit-remaining".to_string(), "42".to_string());

        let parsed = RateLimitHeaders::parse(&headers);
        assert_eq!(parsed.remaining, Some(42));
    }

    // ── suggested_wait edge cases ────────────────────────────────────

    #[test]
    fn suggested_wait_prefers_retry_after_over_reset() {
        let mut headers = RateLimitHeaders::new();
        headers.retry_after = Some(Duration::from_secs(5));
        headers.reset_seconds = Some(60);
        assert_eq!(headers.suggested_wait(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn suggested_wait_falls_back_to_reset_seconds() {
        let mut headers = RateLimitHeaders::new();
        headers.reset_seconds = Some(30);
        assert_eq!(headers.suggested_wait(), Some(Duration::from_secs(30)));
    }

    // ── is_limited combinations ──────────────────────────────────────

    #[test]
    fn is_limited_true_with_retry_after_and_nonzero_remaining() {
        let mut headers = RateLimitHeaders::new();
        headers.remaining = Some(5);
        headers.retry_after = Some(Duration::from_secs(10));
        // retry_after alone makes it limited
        assert!(headers.is_limited());
    }

    // ── parse_duration_string: minute suffix ─────────────────────────

    #[test]
    fn parse_duration_string_minutes() {
        assert_eq!(parse_duration_string("1m"), Some(Duration::from_secs(60)));
        assert_eq!(parse_duration_string("10m"), Some(Duration::from_secs(600)));
    }

    #[test]
    fn parse_duration_string_fractional_seconds() {
        let d = parse_duration_string("0.5s").unwrap();
        assert_eq!(d, Duration::from_secs_f64(0.5));
    }

    // ── Twitter reset in past ────────────────────────────────────────

    #[test]
    fn parse_twitter_reset_in_past() {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let reset_at = now_secs.saturating_sub(50);

        let mut headers = HashMap::new();
        headers.insert("x-rate-limit-reset".to_string(), reset_at.to_string());

        let parsed = RateLimitHeaders::parse_twitter(&headers);
        assert_eq!(parsed.reset_seconds, Some(0));
    }

    // ── OpenAI with seconds duration string ──────────────────────────

    #[test]
    fn parse_openai_reset_requests_seconds_string() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-reset-requests".to_string(), "6s".to_string());

        let parsed = RateLimitHeaders::parse_openai(&headers);
        assert_eq!(parsed.reset_seconds, Some(6));
    }

    // ── Stripe with standard headers ─────────────────────────────────

    #[test]
    fn parse_stripe_includes_standard_fields() {
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "100".to_string());
        headers.insert("x-ratelimit-remaining".to_string(), "0".to_string());
        headers.insert("retry-after".to_string(), "30".to_string());

        let parsed = RateLimitHeaders::parse_stripe(&headers);
        assert_eq!(parsed.limit, Some(100));
        assert_eq!(parsed.remaining, Some(0));
        assert_eq!(parsed.retry_after, Some(Duration::from_secs(30)));
        assert!(parsed.is_limited());
    }

    // ── Provider enum exhaustive ─────────────────────────────────────

    #[test]
    fn provider_all_variants_different() {
        let variants = [
            Provider::Standard,
            Provider::GitHub,
            Provider::Twitter,
            Provider::Stripe,
            Provider::OpenAI,
            Provider::Anthropic,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
