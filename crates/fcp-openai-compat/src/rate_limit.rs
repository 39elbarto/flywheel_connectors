//! Rate-limit header parsing.

use std::time::Duration;

use chrono::Utc;

/// Header list used by the asupersync HTTP client.
pub type HeaderList = Vec<(String, String)>;

const RETRY_AFTER: &str = "retry-after";
const REQUEST_LIMIT: &str = "x-ratelimit-limit-requests";
const REQUEST_REMAINING: &str = "x-ratelimit-remaining-requests";
const REQUEST_RESET: &str = "x-ratelimit-reset-requests";
const TOKEN_LIMIT: &str = "x-ratelimit-limit-tokens";
const TOKEN_REMAINING: &str = "x-ratelimit-remaining-tokens";
const TOKEN_RESET: &str = "x-ratelimit-reset-tokens";

/// Provider-specific rate-limit header overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Request limit header.
    pub request_limit_header: Option<String>,
    /// Remaining request header.
    pub request_remaining_header: Option<String>,
    /// Request reset header.
    pub request_reset_header: Option<String>,
    /// Token limit header.
    pub token_limit_header: Option<String>,
    /// Remaining token header.
    pub token_remaining_header: Option<String>,
    /// Token reset header.
    pub token_reset_header: Option<String>,
    /// Retry-after header.
    pub retry_after_header: Option<String>,
}

/// Parsed rate-limit state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimitSnapshot {
    /// Request limit.
    pub request_limit: Option<u64>,
    /// Remaining requests.
    pub request_remaining: Option<u64>,
    /// Request reset hint.
    pub request_reset_after: Option<Duration>,
    /// Token limit.
    pub token_limit: Option<u64>,
    /// Remaining tokens.
    pub token_remaining: Option<u64>,
    /// Token reset hint.
    pub token_reset_after: Option<Duration>,
    /// Retry-after hint.
    pub retry_after: Option<Duration>,
}

/// Client behavior after a 429 response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RateLimitPolicy {
    /// Return the rate-limit error immediately.
    #[default]
    FailFast,
    /// Wait up to the supplied duration, then retry once.
    WaitUpTo(Duration),
    /// Honor any finite retry-after value and retry once.
    WaitForever,
}

/// Insert or replace a header by case-insensitive name.
pub fn upsert_header(headers: &mut HeaderList, name: impl Into<String>, value: impl Into<String>) {
    let name = name.into();
    let value = value.into();
    if let Some((_, existing)) = headers
        .iter_mut()
        .find(|(header, _)| header.eq_ignore_ascii_case(&name))
    {
        *existing = value;
    } else {
        headers.push((name, value));
    }
}

/// Read a header by case-insensitive name.
#[must_use]
pub fn header_value<'a>(headers: &'a HeaderList, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Parse standard and provider-specific rate-limit headers.
#[must_use]
pub fn parse_rate_limit_headers(
    headers: &HeaderList,
    overrides: Option<&RateLimitConfig>,
) -> RateLimitSnapshot {
    let override_value = |name: Option<&String>, fallback: &str| -> Option<&str> {
        name.and_then(|header| header_value(headers, header))
            .or_else(|| header_value(headers, fallback))
    };

    let config = overrides.cloned().unwrap_or_default();
    RateLimitSnapshot {
        request_limit: override_value(config.request_limit_header.as_ref(), REQUEST_LIMIT)
            .and_then(parse_u64),
        request_remaining: override_value(
            config.request_remaining_header.as_ref(),
            REQUEST_REMAINING,
        )
        .and_then(parse_u64),
        request_reset_after: override_value(config.request_reset_header.as_ref(), REQUEST_RESET)
            .and_then(parse_retry_after),
        token_limit: override_value(config.token_limit_header.as_ref(), TOKEN_LIMIT)
            .and_then(parse_u64),
        token_remaining: override_value(config.token_remaining_header.as_ref(), TOKEN_REMAINING)
            .and_then(parse_u64),
        token_reset_after: override_value(config.token_reset_header.as_ref(), TOKEN_RESET)
            .and_then(parse_retry_after),
        retry_after: override_value(config.retry_after_header.as_ref(), RETRY_AFTER)
            .and_then(parse_retry_after),
    }
}

fn parse_u64(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

/// Parse a Retry-After value as seconds or RFC 2822 HTTP date.
#[must_use]
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u128>() {
        return Some(Duration::from_secs(
            u64::try_from(seconds).unwrap_or(u64::MAX),
        ));
    }

    let retry_at = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let wait = retry_at
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now());
    if wait <= chrono::Duration::zero() {
        Some(Duration::ZERO)
    } else {
        Some(wait.to_std().unwrap_or(Duration::from_secs(u64::MAX)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_standard_headers() {
        let headers = vec![
            (REQUEST_LIMIT.to_string(), "100".to_string()),
            (REQUEST_REMAINING.to_string(), "17".to_string()),
            (RETRY_AFTER.to_string(), "2".to_string()),
        ];

        let parsed = parse_rate_limit_headers(&headers, None);
        assert_eq!(parsed.request_limit, Some(100));
        assert_eq!(parsed.request_remaining, Some(17));
        assert_eq!(parsed.retry_after, Some(Duration::from_secs(2)));
    }

    #[test]
    fn parses_provider_overrides() {
        let headers = vec![("x-groq-ratelimit-remaining".to_string(), "9".to_string())];
        let parsed = parse_rate_limit_headers(
            &headers,
            Some(&RateLimitConfig {
                request_remaining_header: Some("x-groq-ratelimit-remaining".to_string()),
                ..RateLimitConfig::default()
            }),
        );
        assert_eq!(parsed.request_remaining, Some(9));
    }

    #[test]
    fn retry_after_date_in_past_is_zero() {
        let parsed = parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(parsed, Some(Duration::ZERO));
    }

    proptest! {
        #[test]
        fn retry_after_seconds_round_trips(seconds in 0_u64..1_000_000) {
            let parsed = parse_retry_after(&seconds.to_string());
            prop_assert_eq!(parsed, Some(Duration::from_secs(seconds)));
        }
    }
}
