//! OAuth 1.0a implementation for Twitter API authentication.
//!
//! Twitter requires OAuth 1.0a signatures for user-context requests.
//! This module handles generating proper authorization headers.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use sha1::Sha1;

use crate::config::TwitterConfig;
use crate::error::{TwitterError, TwitterResult};

/// Characters that must be percent-encoded in OAuth signatures.
/// RFC 3986 unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
const OAUTH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// OAuth 1.0a signer for Twitter API requests.
#[derive(Debug)]
pub struct OAuthSigner {
    consumer_key: String,
    consumer_secret: String,
    access_token: String,
    access_token_secret: String,
}

impl OAuthSigner {
    /// Create a new OAuth signer from config.
    #[must_use]
    pub fn new(config: &TwitterConfig) -> Self {
        Self {
            consumer_key: config.consumer_key.clone(),
            consumer_secret: config.consumer_secret.clone(),
            access_token: config.access_token.clone(),
            access_token_secret: config.access_token_secret.clone(),
        }
    }

    /// Generate the OAuth 1.0a Authorization header value.
    ///
    /// # Arguments
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `url` - Full URL (without query parameters for signing)
    /// * `params` - Query parameters and body parameters (for POST with form data)
    pub fn sign(
        &self,
        method: &str,
        url: &str,
        params: &[(String, String)],
    ) -> TwitterResult<String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| TwitterError::OAuth(format!("Failed to get timestamp: {e}")))?
            .as_secs()
            .to_string();

        let nonce = generate_nonce();

        // Build OAuth parameters
        let mut oauth_params = vec![
            ("oauth_consumer_key".to_string(), self.consumer_key.clone()),
            ("oauth_nonce".to_string(), nonce),
            (
                "oauth_signature_method".to_string(),
                "HMAC-SHA1".to_string(),
            ),
            ("oauth_timestamp".to_string(), timestamp),
            ("oauth_token".to_string(), self.access_token.clone()),
            ("oauth_version".to_string(), "1.0".to_string()),
        ];

        // Combine OAuth params with request params for signing
        let mut all_params = oauth_params.clone();
        all_params.extend(params.iter().cloned());

        // Sort parameters
        all_params.sort_by(|a, b| {
            if a.0 == b.0 {
                a.1.cmp(&b.1)
            } else {
                a.0.cmp(&b.0)
            }
        });

        // Create parameter string
        let param_string = all_params
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // Create signature base string
        let base_string = format!(
            "{}&{}&{}",
            method.to_uppercase(),
            percent_encode(url),
            percent_encode(&param_string)
        );

        // Create signing key
        let signing_key = format!(
            "{}&{}",
            percent_encode(&self.consumer_secret),
            percent_encode(&self.access_token_secret)
        );

        // Generate HMAC-SHA1 signature
        let signature = hmac_sha1(&signing_key, &base_string)?;

        // Add signature to OAuth params
        oauth_params.push(("oauth_signature".to_string(), signature));

        // Build Authorization header
        let header = oauth_params
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join(", ");

        Ok(format!("OAuth {header}"))
    }
}

/// Percent-encode a string according to RFC 3986.
fn percent_encode(s: &str) -> String {
    utf8_percent_encode(s, OAUTH_ENCODE_SET).to_string()
}

/// Generate a random nonce for OAuth.
fn generate_nonce() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute HMAC-SHA1 and return base64-encoded result.
fn hmac_sha1(key: &str, data: &str) -> TwitterResult<String> {
    type HmacSha1 = Hmac<Sha1>;

    let mut mac =
        HmacSha1::new_from_slice(key.as_bytes()).map_err(|e| TwitterError::OAuth(e.to_string()))?;

    mac.update(data.as_bytes());
    let result = mac.finalize();
    Ok(BASE64.encode(result.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(percent_encode("foo=bar&baz"), "foo%3Dbar%26baz");
        assert_eq!(percent_encode("test-value_123.txt"), "test-value_123.txt");
        assert_eq!(percent_encode("~tilde"), "~tilde");
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Nonces should be different
        assert_ne!(nonce1, nonce2);

        // Nonces should be 32 hex characters
        assert_eq!(nonce1.len(), 32);
        assert!(nonce1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_oauth_signer_creates_valid_header() {
        let config = TwitterConfig {
            consumer_key: "test_consumer_key".into(),
            consumer_secret: "test_consumer_secret".into(),
            access_token: "test_access_token".into(),
            access_token_secret: "test_access_token_secret".into(),
            ..Default::default()
        };

        let signer = OAuthSigner::new(&config);
        let header = signer
            .sign("GET", "https://api.twitter.com/2/users/me", &[])
            .unwrap();

        assert!(header.starts_with("OAuth "));
        assert!(header.contains("oauth_consumer_key="));
        assert!(header.contains("oauth_signature="));
        assert!(header.contains("oauth_timestamp="));
        assert!(header.contains("oauth_nonce="));
    }
}
