//! Wolfram Alpha API types.

use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// Production Wolfram Alpha API host allowed by the connector manifest.
pub const WOLFRAM_PRODUCTION_HOST: &str = "api.wolframalpha.com";

/// Canonical production Wolfram Alpha API origin.
pub const WOLFRAM_PRODUCTION_BASE_URL: &str = "https://api.wolframalpha.com";

/// Configuration for the Wolfram Alpha connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolframConfig {
    /// Wolfram Alpha App ID (credential reference for secretless mode).
    pub credential_id: fcp_core::CredentialId,

    /// Base URL override (for testing).
    #[serde(default = "default_base_url")]
    pub base_url: String,

    /// Explicitly allow loopback mock endpoints in debug/test builds.
    #[serde(default)]
    pub allow_mock_base_url: bool,

    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_base_url() -> String {
    WOLFRAM_PRODUCTION_HOST.into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

/// Runtime classification for a validated Wolfram base URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WolframBaseUrlMode {
    /// Production traffic to the manifest-pinned Wolfram Alpha host.
    Production,
    /// Debug/test traffic to an explicit loopback mock server.
    MockLoopback,
}

/// Canonicalized base URL policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WolframBaseUrlPolicy {
    /// Canonical origin string with no path/query/fragment.
    pub canonical_url: String,
    /// Whether this endpoint is production or an explicit mock seam.
    pub mode: WolframBaseUrlMode,
}

impl WolframBaseUrlPolicy {
    #[must_use]
    pub fn production() -> Self {
        Self {
            canonical_url: WOLFRAM_PRODUCTION_BASE_URL.into(),
            mode: WolframBaseUrlMode::Production,
        }
    }
}

/// Validate and canonicalize the configured Wolfram base URL.
pub fn validate_wolfram_base_url(
    raw: &str,
    allow_mock_base_url: bool,
) -> Result<WolframBaseUrlPolicy, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("base_url must not be empty".into());
    }

    let parse_input = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };

    let url = Url::parse(&parse_input)
        .map_err(|error| format!("base_url must be a valid absolute URL or host: {error}"))?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err("base_url must not contain userinfo".into());
    }
    if url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        return Err("base_url must be an origin without path, query, or fragment".into());
    }

    let host = url
        .host()
        .ok_or_else(|| "base_url must include a host".to_string())?;

    let is_production_host = match &host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case(WOLFRAM_PRODUCTION_HOST),
        Host::Ipv4(_) | Host::Ipv6(_) => false,
    };
    if is_production_host {
        return validate_production_base_url(&url);
    }

    validate_mock_base_url(&url, &host, allow_mock_base_url)
}

fn validate_production_base_url(url: &Url) -> Result<WolframBaseUrlPolicy, String> {
    if url.scheme() != "https" {
        return Err(format!(
            "production base_url must use https://{WOLFRAM_PRODUCTION_HOST}"
        ));
    }
    if url.port_or_known_default() != Some(443) {
        return Err("production base_url must use TLS port 443".into());
    }

    Ok(WolframBaseUrlPolicy::production())
}

fn validate_mock_base_url(
    url: &Url,
    host: &Host<&str>,
    allow_mock_base_url: bool,
) -> Result<WolframBaseUrlPolicy, String> {
    if !allow_mock_base_url {
        return Err(format!(
            "base_url must be exactly {WOLFRAM_PRODUCTION_BASE_URL}; loopback mocks require allow_mock_base_url=true"
        ));
    }
    if !cfg!(debug_assertions) {
        return Err("loopback mock base_url values are disabled in release builds".into());
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err("mock base_url must use http or https".into());
    }
    if url.port().is_none() {
        return Err("mock base_url must include an explicit loopback port".into());
    }
    if !is_loopback_host(host) {
        return Err("mock base_url must use localhost, 127.0.0.1, or ::1".into());
    }

    Ok(WolframBaseUrlPolicy {
        canonical_url: canonical_origin(url),
        mode: WolframBaseUrlMode::MockLoopback,
    })
}

fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(addr) => addr.is_loopback(),
        Host::Ipv6(addr) => addr.is_loopback(),
    }
}

fn canonical_origin(url: &Url) -> String {
    let mut canonical = url.clone();
    canonical.set_path("");
    canonical.set_query(None);
    canonical.set_fragment(None);
    canonical.to_string().trim_end_matches('/').to_string()
}

/// Full query result from the Wolfram Alpha API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Whether the query was successful.
    pub success: bool,

    /// Number of pods returned.
    #[serde(default)]
    pub numpods: u32,

    /// The pods containing results.
    #[serde(default)]
    pub pods: Vec<Pod>,

    /// Timing information.
    #[serde(default)]
    pub timing: Option<f64>,

    /// Whether there are related assumptions.
    #[serde(default)]
    pub assumptions: Vec<Assumption>,
}

/// A pod in the Wolfram Alpha result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pod {
    /// Pod title (e.g., "Result", "Input interpretation").
    pub title: String,

    /// Pod ID.
    pub id: String,

    /// Number of subpods.
    #[serde(default)]
    pub numsubpods: u32,

    /// Whether this pod is the primary result.
    #[serde(default)]
    pub primary: bool,

    /// Subpods containing the actual data.
    #[serde(default)]
    pub subpods: Vec<SubPod>,
}

/// A subpod within a pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubPod {
    /// Title of the subpod (often empty).
    #[serde(default)]
    pub title: String,

    /// Plain text representation of the result.
    #[serde(default)]
    pub plaintext: Option<String>,

    /// Image representation.
    #[serde(default)]
    pub img: Option<ImageInfo>,
}

/// Image information for a subpod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image URL.
    pub src: String,

    /// Image alt text.
    #[serde(default)]
    pub alt: String,

    /// Image width.
    #[serde(default)]
    pub width: u32,

    /// Image height.
    #[serde(default)]
    pub height: u32,
}

/// An assumption about the query interpretation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assumption {
    /// Assumption type.
    #[serde(rename = "type")]
    pub assumption_type: String,

    /// Word being assumed.
    #[serde(default)]
    pub word: Option<String>,

    /// Possible values for the assumption.
    #[serde(default)]
    pub values: Vec<AssumptionValue>,
}

/// A possible value for an assumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssumptionValue {
    /// Display name.
    pub name: String,

    /// Internal description.
    #[serde(default)]
    pub desc: Option<String>,

    /// Input value for selecting this assumption.
    #[serde(default)]
    pub input: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_base_url() {
        let config: WolframConfig = serde_json::from_value(serde_json::json!({
            "credential_id": fcp_core::CredentialId::new()
        }))
        .expect("parse config");
        assert_eq!(config.base_url, "api.wolframalpha.com");
        assert!(!config.allow_mock_base_url);
        assert_eq!(config.timeout_ms, 30_000);
    }

    #[test]
    fn config_custom_base_url() {
        let config: WolframConfig = serde_json::from_value(serde_json::json!({
            "credential_id": fcp_core::CredentialId::new(),
            "base_url": "test.example.com",
            "timeout_ms": 5000
        }))
        .expect("parse config");
        assert_eq!(config.base_url, "test.example.com");
        assert!(!config.allow_mock_base_url);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn base_url_policy_accepts_and_canonicalizes_production_host() {
        for raw in [
            "api.wolframalpha.com",
            "API.WOLFRAMALPHA.COM",
            "https://api.wolframalpha.com",
            "https://api.wolframalpha.com:443/",
        ] {
            let policy = validate_wolfram_base_url(raw, false).expect("production host");
            assert_eq!(policy.mode, WolframBaseUrlMode::Production);
            assert_eq!(policy.canonical_url, WOLFRAM_PRODUCTION_BASE_URL);
        }
    }

    #[test]
    fn base_url_policy_rejects_production_http() {
        let error = validate_wolfram_base_url("http://api.wolframalpha.com", false)
            .expect_err("http production must fail");
        assert!(error.contains("https"));
    }

    #[test]
    fn base_url_policy_rejects_substring_hosts() {
        for raw in [
            "api.wolframalpha.com.evil.example",
            "https://evil-wolframalpha.com",
            "https://wolfram.com",
        ] {
            let error = validate_wolfram_base_url(raw, false).expect_err("substring host");
            assert!(error.contains(WOLFRAM_PRODUCTION_BASE_URL));
        }
    }

    #[test]
    fn base_url_policy_rejects_userinfo() {
        let error = validate_wolfram_base_url("https://user@api.wolframalpha.com", false)
            .expect_err("userinfo must fail");
        assert!(error.contains("userinfo"));
    }

    #[test]
    fn base_url_policy_rejects_local_and_private_hosts_without_mock_seam() {
        for raw in [
            "http://127.0.0.1:1234",
            "http://localhost:1234",
            "http://[::1]:1234",
            "http://10.0.0.10:1234",
            "http://192.168.1.12:1234",
        ] {
            let error = validate_wolfram_base_url(raw, false).expect_err("local/private host");
            assert!(error.contains("allow_mock_base_url"));
        }
    }

    #[test]
    fn base_url_policy_accepts_loopback_only_with_mock_seam() {
        let policy =
            validate_wolfram_base_url("http://127.0.0.1:1234", true).expect("loopback mock");
        assert_eq!(policy.mode, WolframBaseUrlMode::MockLoopback);
        assert_eq!(policy.canonical_url, "http://127.0.0.1:1234");

        let error = validate_wolfram_base_url("http://192.168.1.12:1234", true)
            .expect_err("private mock host");
        assert!(error.contains("localhost"));
    }

    #[test]
    fn query_result_deserialization() {
        let json = serde_json::json!({
            "success": true,
            "numpods": 2,
            "pods": [
                {
                    "title": "Input interpretation",
                    "id": "Input",
                    "numsubpods": 1,
                    "primary": false,
                    "subpods": [{"plaintext": "2 + 2"}]
                },
                {
                    "title": "Result",
                    "id": "Result",
                    "numsubpods": 1,
                    "primary": true,
                    "subpods": [{"plaintext": "4"}]
                }
            ],
            "timing": 0.5,
            "assumptions": []
        });
        let result: QueryResult = serde_json::from_value(json).expect("parse result");
        assert!(result.success);
        assert_eq!(result.numpods, 2);
        assert_eq!(result.pods.len(), 2);
        assert!(result.pods[1].primary);
        assert_eq!(result.pods[1].subpods[0].plaintext.as_deref(), Some("4"));
    }

    #[test]
    fn pod_with_image() {
        let json = serde_json::json!({
            "title": "Plot",
            "id": "Plot",
            "subpods": [{
                "title": "",
                "img": {
                    "src": "https://api.wolframalpha.com/img/123",
                    "alt": "plot",
                    "width": 200,
                    "height": 150
                }
            }]
        });
        let pod: Pod = serde_json::from_value(json).expect("parse pod");
        let img = pod.subpods[0].img.as_ref().expect("image");
        assert_eq!(img.width, 200);
        assert_eq!(img.height, 150);
    }

    #[test]
    fn assumption_deserialization() {
        let json = serde_json::json!({
            "type": "Clash",
            "word": "mercury",
            "values": [
                {"name": "Planet", "desc": "a planet", "input": "Mercury_P"},
                {"name": "Element", "desc": "a chemical element", "input": "Mercury_E"}
            ]
        });
        let assumption: Assumption = serde_json::from_value(json).expect("parse assumption");
        assert_eq!(assumption.assumption_type, "Clash");
        assert_eq!(assumption.word.as_deref(), Some("mercury"));
        assert_eq!(assumption.values.len(), 2);
    }
}
