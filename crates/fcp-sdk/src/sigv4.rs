//! AWS Signature Version 4 signing for FCP connectors.
//!
//! Implements the AWS SigV4 signing process as documented in the
//! [AWS Signature Version 4 documentation](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html).
//!
//! This module provides a shared, correct SigV4 implementation that
//! AWS-family connectors (aws, s3, dynamodb, etc.) can use instead of
//! rolling their own partial signing logic.
//!
//! # Features
//!
//! - Canonical request assembly (sorted headers, encoded URI/query)
//! - HMAC-SHA256 signing key derivation
//! - Authorization header generation
//! - Query string presigning for temporary URLs
//! - Clock injection for deterministic testing
//! - Redaction-safe debug output (credentials never logged)

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// ── Credentials ─────────────────────────────────────────────────────────

/// AWS credentials for SigV4 signing.
///
/// Debug output redacts secret_access_key and session_token.
#[derive(Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

// ── Signing Scope ───────────────────────────────────────────────────────

/// Scope for SigV4 signing (date/region/service).
#[derive(Debug, Clone)]
pub struct SigningScope {
    /// AWS region (e.g., "us-east-1").
    pub region: String,
    /// AWS service (e.g., "s3", "ec2", "execute-api").
    pub service: String,
}

// ── Request to Sign ─────────────────────────────────────────────────────

/// HTTP request components needed for SigV4 signing.
#[derive(Debug, Clone)]
pub struct SignableRequest {
    /// HTTP method (GET, PUT, POST, DELETE, etc.).
    pub method: String,
    /// URI path (e.g., "/bucket/key").
    pub uri: String,
    /// Query string parameters (key → value).
    pub query_params: BTreeMap<String, String>,
    /// HTTP headers (lowercase key → value).
    pub headers: BTreeMap<String, String>,
    /// SHA-256 hash of the request body (hex-encoded).
    /// Use `UNSIGNED_PAYLOAD` for unsigned payloads (e.g., S3 streaming).
    pub payload_hash: String,
}

/// Sentinel value for unsigned payloads.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Sentinel value for empty body.
pub const EMPTY_PAYLOAD_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

impl SignableRequest {
    /// Compute the SHA-256 hash of a payload.
    #[must_use]
    pub fn hash_payload(payload: &[u8]) -> String {
        hex::encode(Sha256::digest(payload))
    }
}

// ── Signed Output ───────────────────────────────────────────────────────

/// Result of SigV4 signing — the Authorization header value and
/// signed headers list.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// The full Authorization header value.
    pub authorization: String,
    /// ISO 8601 timestamp used for signing.
    pub x_amz_date: String,
    /// Security token header (if session credentials).
    pub x_amz_security_token: Option<String>,
    /// SHA-256 content hash header.
    pub x_amz_content_sha256: String,
}

/// Result of query string presigning.
#[derive(Debug, Clone)]
pub struct PresignedUrl {
    /// The presigned URL with SigV4 query parameters.
    pub url: String,
    /// When the presigned URL expires.
    pub expires_in_secs: u64,
}

// ── Signer ──────────────────────────────────────────────────────────────

/// AWS SigV4 signer with deterministic clock injection.
#[derive(Debug, Clone)]
pub struct SigV4Signer {
    credentials: AwsCredentials,
    scope: SigningScope,
    /// Fixed timestamp for deterministic testing. If None, uses Utc::now().
    fixed_time: Option<DateTime<Utc>>,
}

impl SigV4Signer {
    /// Create a new signer.
    #[must_use]
    pub fn new(credentials: AwsCredentials, scope: SigningScope) -> Self {
        Self {
            credentials,
            scope,
            fixed_time: None,
        }
    }

    /// Create a signer with a fixed timestamp (for deterministic tests).
    #[must_use]
    pub fn with_fixed_time(mut self, time: DateTime<Utc>) -> Self {
        self.fixed_time = Some(time);
        self
    }

    /// Sign a request and return the Authorization header components.
    #[must_use]
    pub fn sign(&self, request: &SignableRequest) -> SignedRequest {
        let now = self.now();
        let date_stamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        let credential_scope =
            format!("{date_stamp}/{}/{}/aws4_request", self.scope.region, self.scope.service);

        // Step 1: Canonical request
        let (canonical_request, signed_headers) =
            self.build_canonical_request(request, &amz_date);

        // Step 2: String to sign
        let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}"
        );

        // Step 3: Signing key
        let signing_key = self.derive_signing_key(&date_stamp);

        // Step 4: Signature
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        // Step 5: Authorization header
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.credentials.access_key_id,
        );

        SignedRequest {
            authorization,
            x_amz_date: amz_date,
            x_amz_security_token: self.credentials.session_token.clone(),
            x_amz_content_sha256: request.payload_hash.clone(),
        }
    }

    /// Generate a presigned URL with SigV4 query string signing.
    #[must_use]
    pub fn presign(&self, request: &SignableRequest, expires_in_secs: u64) -> PresignedUrl {
        let now = self.now();
        let date_stamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        let credential_scope =
            format!("{date_stamp}/{}/{}/aws4_request", self.scope.region, self.scope.service);
        let credential =
            format!("{}/{credential_scope}", self.credentials.access_key_id);

        // Build query params for presigning
        let mut query = request.query_params.clone();
        query.insert("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into());
        query.insert("X-Amz-Credential".into(), credential);
        query.insert("X-Amz-Date".into(), amz_date.clone());
        query.insert("X-Amz-Expires".into(), expires_in_secs.to_string());
        query.insert("X-Amz-SignedHeaders".into(), "host".into());
        if let Some(token) = &self.credentials.session_token {
            query.insert("X-Amz-Security-Token".into(), token.clone());
        }

        // Canonical request with UNSIGNED-PAYLOAD
        let canonical_query = build_canonical_query(&query);
        let canonical_headers = request
            .headers
            .iter()
            .filter(|(k, _)| k.as_str() == "host")
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect::<String>();

        let canonical_request = format!(
            "{}\n{}\n{canonical_query}\n{canonical_headers}\nhost\n{UNSIGNED_PAYLOAD}",
            request.method, request.uri,
        );

        let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}"
        );

        let signing_key = self.derive_signing_key(&date_stamp);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        query.insert("X-Amz-Signature".into(), signature);

        let final_query = build_canonical_query(&query);
        let url = format!("{}?{final_query}", request.uri);

        PresignedUrl {
            url,
            expires_in_secs,
        }
    }

    // ── Internal ────────────────────────────────────────────────────

    fn now(&self) -> DateTime<Utc> {
        self.fixed_time.unwrap_or_else(Utc::now)
    }

    /// Build the canonical request string and return (canonical_request, signed_headers).
    fn build_canonical_request(
        &self,
        request: &SignableRequest,
        amz_date: &str,
    ) -> (String, String) {
        // Canonical URI
        let canonical_uri = uri_encode_path(&request.uri);

        // Canonical query string (sorted by key)
        let canonical_query = build_canonical_query(&request.query_params);

        // Canonical headers (sorted, lowercase, trimmed)
        let mut headers = request.headers.clone();
        headers.entry("x-amz-date".into()).or_insert_with(|| amz_date.into());
        headers
            .entry("x-amz-content-sha256".into())
            .or_insert_with(|| request.payload_hash.clone());
        if let Some(token) = &self.credentials.session_token {
            headers
                .entry("x-amz-security-token".into())
                .or_insert_with(|| token.clone());
        }

        let canonical_headers: String = headers
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k.to_lowercase(), v.trim()))
            .collect();

        let signed_headers: String = headers
            .keys()
            .map(|k| k.to_lowercase())
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "{}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{}",
            request.method, request.payload_hash,
        );

        (canonical_request, signed_headers)
    }

    /// Derive the SigV4 signing key via successive HMAC rounds.
    fn derive_signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_date = hmac_sha256(
            format!("AWS4{}", self.credentials.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.scope.region.as_bytes());
        let k_service = hmac_sha256(&k_region, self.scope.service.as_bytes());
        hmac_sha256(&k_service, b"aws4_request")
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// URI-encode a single component per AWS SigV4 rules.
/// Unreserved chars (A-Z, a-z, 0-9, '-', '_', '.', '~') are not encoded.
fn uri_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

fn uri_encode_path(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    path.split('/')
        .map(|segment| uri_encode(segment))
        .collect::<Vec<_>>()
        .join("/")
}

fn build_canonical_query(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_credentials() -> AwsCredentials {
        AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    fn test_scope() -> SigningScope {
        SigningScope {
            region: "us-east-1".into(),
            service: "s3".into(),
        }
    }

    fn fixed_time() -> DateTime<Utc> {
        "2013-05-24T00:00:00Z".parse().unwrap()
    }

    fn test_signer() -> SigV4Signer {
        SigV4Signer::new(test_credentials(), test_scope()).with_fixed_time(fixed_time())
    }

    // ── Signing Key Derivation ───────────────────────────────────

    #[test]
    fn signing_key_derivation_is_deterministic() {
        let signer = test_signer();
        let key1 = signer.derive_signing_key("20130524");
        let key2 = signer.derive_signing_key("20130524");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32); // HMAC-SHA256 output
    }

    #[test]
    fn signing_key_differs_by_date() {
        let signer = test_signer();
        let key1 = signer.derive_signing_key("20130524");
        let key2 = signer.derive_signing_key("20130525");
        assert_ne!(key1, key2);
    }

    #[test]
    fn signing_key_differs_by_region() {
        let signer1 = SigV4Signer::new(
            test_credentials(),
            SigningScope { region: "us-east-1".into(), service: "s3".into() },
        );
        let signer2 = SigV4Signer::new(
            test_credentials(),
            SigningScope { region: "eu-west-1".into(), service: "s3".into() },
        );
        assert_ne!(
            signer1.derive_signing_key("20130524"),
            signer2.derive_signing_key("20130524"),
        );
    }

    #[test]
    fn signing_key_differs_by_service() {
        let signer1 = SigV4Signer::new(
            test_credentials(),
            SigningScope { region: "us-east-1".into(), service: "s3".into() },
        );
        let signer2 = SigV4Signer::new(
            test_credentials(),
            SigningScope { region: "us-east-1".into(), service: "ec2".into() },
        );
        assert_ne!(
            signer1.derive_signing_key("20130524"),
            signer2.derive_signing_key("20130524"),
        );
    }

    // ── Canonical Request ────────────────────────────────────────

    #[test]
    fn canonical_request_sorts_headers() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([
                ("host".into(), "example.amazonaws.com".into()),
                ("x-amz-date".into(), "20130524T000000Z".into()),
            ]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let (canonical, signed) =
            signer.build_canonical_request(&request, "20130524T000000Z");

        assert!(canonical.contains("host:example.amazonaws.com"));
        assert!(signed.contains("host"));
        assert!(signed.contains("x-amz-date"));
    }

    #[test]
    fn canonical_query_string_sorted_by_key() {
        let params = BTreeMap::from([
            ("z-param".into(), "value2".into()),
            ("a-param".into(), "value1".into()),
        ]);
        let result = build_canonical_query(&params);
        // BTreeMap sorts by raw key; '-' is unreserved so not encoded
        assert!(result.starts_with("a-param"), "got: {result}");
    }

    // ── Full Signing ─────────────────────────────────────────────

    #[test]
    fn sign_produces_valid_authorization_header() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/test.txt".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([
                ("host".into(), "examplebucket.s3.amazonaws.com".into()),
            ]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let signed = signer.sign(&request);

        assert!(signed.authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(signed.authorization.contains("SignedHeaders="));
        assert!(signed.authorization.contains("Signature="));
        assert_eq!(signed.x_amz_date, "20130524T000000Z");
        assert_eq!(signed.x_amz_content_sha256, EMPTY_PAYLOAD_HASH);
        assert!(signed.x_amz_security_token.is_none());
    }

    #[test]
    fn sign_is_deterministic_with_fixed_time() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([
                ("host".into(), "example.amazonaws.com".into()),
            ]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let signed1 = signer.sign(&request);
        let signed2 = signer.sign(&request);
        assert_eq!(signed1.authorization, signed2.authorization);
    }

    #[test]
    fn sign_includes_session_token_when_present() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("FwoGZXIvYXdzEBYaDHqa0AF".into()),
        };
        let signer =
            SigV4Signer::new(creds, test_scope()).with_fixed_time(fixed_time());

        let request = SignableRequest {
            method: "GET".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([
                ("host".into(), "example.amazonaws.com".into()),
            ]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let signed = signer.sign(&request);
        assert!(signed.x_amz_security_token.is_some());
        assert!(signed.authorization.contains("x-amz-security-token"));
    }

    // ── Presigning ───────────────────────────────────────────────

    #[test]
    fn presign_produces_url_with_sigv4_params() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/test-bucket/test-key.txt".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([
                ("host".into(), "s3.amazonaws.com".into()),
            ]),
            payload_hash: UNSIGNED_PAYLOAD.into(),
        };

        let presigned = signer.presign(&request, 3600);

        assert!(presigned.url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(presigned.url.contains("X-Amz-Credential="));
        assert!(presigned.url.contains("X-Amz-Date="));
        assert!(presigned.url.contains("X-Amz-Expires=3600"));
        assert!(presigned.url.contains("X-Amz-Signature="));
        assert!(presigned.url.contains("X-Amz-SignedHeaders=host"));
        assert_eq!(presigned.expires_in_secs, 3600);
    }

    #[test]
    fn presign_is_deterministic() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/bucket/key".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([
                ("host".into(), "s3.amazonaws.com".into()),
            ]),
            payload_hash: UNSIGNED_PAYLOAD.into(),
        };

        let url1 = signer.presign(&request, 900);
        let url2 = signer.presign(&request, 900);
        assert_eq!(url1.url, url2.url);
    }

    // ── Payload Hashing ──────────────────────────────────────────

    #[test]
    fn empty_payload_hash_matches_constant() {
        assert_eq!(SignableRequest::hash_payload(b""), EMPTY_PAYLOAD_HASH);
    }

    #[test]
    fn payload_hash_is_deterministic() {
        let hash1 = SignableRequest::hash_payload(b"hello world");
        let hash2 = SignableRequest::hash_payload(b"hello world");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, EMPTY_PAYLOAD_HASH);
    }

    // ── Credential Redaction ─────────────────────────────────────

    #[test]
    fn debug_output_redacts_secrets() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("token123".into()),
        };
        let debug = format!("{creds:?}");
        assert!(debug.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!debug.contains("wJalrXUtnFEMI"));
        assert!(!debug.contains("token123"));
        assert!(debug.contains("[REDACTED]"));
    }

    // ── URI Encoding ─────────────────────────────────────────────

    #[test]
    fn uri_encode_empty_path_becomes_slash() {
        assert_eq!(uri_encode_path(""), "/");
    }

    #[test]
    fn uri_encode_preserves_slashes() {
        let encoded = uri_encode_path("/bucket/key/with/slashes");
        assert!(encoded.starts_with('/'));
        assert!(encoded.contains('/'));
    }
}
