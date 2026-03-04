//! Browser automation API types.

use serde::{Deserialize, Serialize};

/// Result of a navigation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigateResult {
    pub url: String,
    pub status: u16,
    pub title: Option<String>,
}

/// Result of a screenshot operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotResult {
    pub image_data: String,
    pub width: u32,
    pub height: u32,
}

/// Result of a PDF render operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfResult {
    pub pdf_data: String,
    pub page_count: u32,
}

/// Result of a text extraction operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextResult {
    pub text: String,
    pub word_count: Option<u64>,
}

/// A single extracted link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkEntry {
    pub href: String,
    pub text: Option<String>,
}

/// Result of a link extraction operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinksResult {
    pub links: Vec<LinkEntry>,
}

/// Result of a click operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickResult {
    pub clicked: bool,
    pub navigation_url: Option<String>,
}

/// Result of a form fill operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormResult {
    pub filled_count: u32,
    pub submitted: Option<bool>,
}

/// Result of a JavaScript evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsResult {
    pub result: String,
}

/// A browser cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<f64>,
    pub http_only: Option<bool>,
    pub secure: Option<bool>,
    pub same_site: Option<String>,
}

/// Proxy configuration for browser network routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub server: String,
    pub bypass_list: Option<Vec<String>>,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Result of proxy configuration operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResult {
    pub enabled: bool,
    pub mode: String,
    pub server: Option<String>,
}

/// Result of a wait-for-selector operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitResult {
    pub found: bool,
}

/// Browser API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiErrorDetail>,
}

/// Browser error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    pub message: Option<String>,
    pub code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn navigate_result_serde() {
        let result = NavigateResult {
            url: "https://example.com".to_string(),
            status: 200,
            title: Some("Example".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: NavigateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, 200);
    }

    #[test]
    fn screenshot_result_serde() {
        let result = ScreenshotResult {
            image_data: "base64data".to_string(),
            width: 1920,
            height: 1080,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ScreenshotResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.width, 1920);
    }

    #[test]
    fn pdf_result_serde() {
        let result = PdfResult {
            pdf_data: "base64pdf".to_string(),
            page_count: 5,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: PdfResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.page_count, 5);
    }

    #[test]
    fn text_result_serde() {
        let result = TextResult {
            text: "Hello world".to_string(),
            word_count: Some(2),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TextResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.word_count, Some(2));
    }

    #[test]
    fn links_result_serde() {
        let result = LinksResult {
            links: vec![LinkEntry {
                href: "https://example.com".to_string(),
                text: Some("Example".to_string()),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: LinksResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.links.len(), 1);
    }

    #[test]
    fn click_result_serde() {
        let result = ClickResult { clicked: true, navigation_url: None };
        let json = serde_json::to_string(&result).unwrap();
        let back: ClickResult = serde_json::from_str(&json).unwrap();
        assert!(back.clicked);
    }

    #[test]
    fn form_result_serde() {
        let result = FormResult { filled_count: 3, submitted: Some(true) };
        let json = serde_json::to_string(&result).unwrap();
        let back: FormResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.filled_count, 3);
    }

    #[test]
    fn cookie_serde() {
        let cookie = Cookie {
            name: "session".to_string(),
            value: "abc123".to_string(),
            domain: Some(".example.com".to_string()),
            path: Some("/".to_string()),
            expires: Some(1_700_000_000.0),
            http_only: Some(true),
            secure: Some(true),
            same_site: Some("Lax".to_string()),
        };
        let json = serde_json::to_string(&cookie).unwrap();
        let back: Cookie = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "session");
        assert!(back.http_only.unwrap());
    }

    #[test]
    fn proxy_config_serde() {
        let config = ProxyConfig {
            server: "http://proxy:8080".to_string(),
            bypass_list: Some(vec!["localhost".to_string()]),
            username: None,
            password: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.server, "http://proxy:8080");
    }

    #[test]
    fn api_error_response_serde() {
        let json = json!({"error": {"message": "timeout", "code": "TIMEOUT"}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.unwrap().code.as_deref(), Some("TIMEOUT"));
    }
}
