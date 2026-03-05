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

    // ─────────────────────────────────────────────────────────────────────────
    // NavigateResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn navigate_result_roundtrip() {
        let result = NavigateResult {
            url: "https://example.com".to_string(),
            status: 200,
            title: Some("Example".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: NavigateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.url, "https://example.com");
        assert_eq!(back.status, 200);
        assert_eq!(back.title.as_deref(), Some("Example"));
    }

    #[test]
    fn navigate_result_title_none() {
        let result = NavigateResult {
            url: "https://example.com".to_string(),
            status: 204,
            title: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: NavigateResult = serde_json::from_str(&json).unwrap();
        assert!(back.title.is_none());
    }

    #[test]
    fn navigate_result_from_json_with_null_title() {
        let v = json!({"url": "https://x.com", "status": 200, "title": null});
        let result: NavigateResult = serde_json::from_value(v).unwrap();
        assert!(result.title.is_none());
    }

    #[test]
    fn navigate_result_from_json_missing_title() {
        // serde deserializes missing Option fields as None
        let v = json!({"url": "https://x.com", "status": 200});
        let result: NavigateResult = serde_json::from_value(v).unwrap();
        assert!(result.title.is_none());
        assert_eq!(result.status, 200);
    }

    #[test]
    fn navigate_result_clone() {
        let result = NavigateResult {
            url: "https://example.com".to_string(),
            status: 200,
            title: Some("Example".to_string()),
        };
        let cloned = result.clone();
        assert_eq!(cloned.url, result.url);
        assert_eq!(cloned.status, result.status);
        assert_eq!(cloned.title, result.title);
    }

    #[test]
    fn navigate_result_debug() {
        let result = NavigateResult {
            url: "https://example.com".to_string(),
            status: 200,
            title: None,
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("NavigateResult"));
        assert!(dbg.contains("200"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ScreenshotResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn screenshot_result_roundtrip() {
        let result = ScreenshotResult {
            image_data: "base64data".to_string(),
            width: 1920,
            height: 1080,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ScreenshotResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.image_data, "base64data");
        assert_eq!(back.width, 1920);
        assert_eq!(back.height, 1080);
    }

    #[test]
    fn screenshot_result_zero_dimensions() {
        let result = ScreenshotResult {
            image_data: String::new(),
            width: 0,
            height: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ScreenshotResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.width, 0);
        assert_eq!(back.height, 0);
    }

    #[test]
    fn screenshot_result_clone() {
        let result = ScreenshotResult {
            image_data: "abc".to_string(),
            width: 800,
            height: 600,
        };
        let cloned = result.clone();
        assert_eq!(cloned.image_data, "abc");
        assert_eq!(result.width, 800);
    }

    #[test]
    fn screenshot_result_debug() {
        let result = ScreenshotResult {
            image_data: "x".to_string(),
            width: 1,
            height: 1,
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("ScreenshotResult"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PdfResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn pdf_result_roundtrip() {
        let result = PdfResult {
            pdf_data: "base64pdf".to_string(),
            page_count: 5,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: PdfResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pdf_data, "base64pdf");
        assert_eq!(back.page_count, 5);
    }

    #[test]
    fn pdf_result_zero_pages() {
        let result = PdfResult {
            pdf_data: String::new(),
            page_count: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: PdfResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.page_count, 0);
    }

    #[test]
    fn pdf_result_clone_and_debug() {
        let result = PdfResult {
            pdf_data: "data".to_string(),
            page_count: 10,
        };
        let cloned = result.clone();
        assert_eq!(cloned.page_count, 10);
        let dbg = format!("{result:?}");
        assert!(dbg.contains("PdfResult"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TextResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn text_result_roundtrip() {
        let result = TextResult {
            text: "Hello world".to_string(),
            word_count: Some(2),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TextResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.text, "Hello world");
        assert_eq!(back.word_count, Some(2));
    }

    #[test]
    fn text_result_word_count_none() {
        let result = TextResult {
            text: "Hello".to_string(),
            word_count: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TextResult = serde_json::from_str(&json).unwrap();
        assert!(back.word_count.is_none());
    }

    #[test]
    fn text_result_from_json_null_word_count() {
        let v = json!({"text": "hi", "word_count": null});
        let result: TextResult = serde_json::from_value(v).unwrap();
        assert!(result.word_count.is_none());
    }

    #[test]
    fn text_result_empty_text() {
        let result = TextResult {
            text: String::new(),
            word_count: Some(0),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TextResult = serde_json::from_str(&json).unwrap();
        assert!(back.text.is_empty());
        assert_eq!(back.word_count, Some(0));
    }

    #[test]
    fn text_result_large_word_count() {
        let result = TextResult {
            text: "lots of words".to_string(),
            word_count: Some(u64::MAX),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TextResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.word_count, Some(u64::MAX));
    }

    #[test]
    fn text_result_clone_and_debug() {
        let result = TextResult {
            text: "test".to_string(),
            word_count: Some(1),
        };
        let cloned = result.clone();
        assert_eq!(cloned.text, "test");
        let dbg = format!("{result:?}");
        assert!(dbg.contains("TextResult"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LinkEntry
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn link_entry_roundtrip() {
        let link = LinkEntry {
            href: "https://example.com".to_string(),
            text: Some("Example".to_string()),
        };
        let json = serde_json::to_string(&link).unwrap();
        let back: LinkEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.href, "https://example.com");
        assert_eq!(back.text.as_deref(), Some("Example"));
    }

    #[test]
    fn link_entry_text_none() {
        let link = LinkEntry {
            href: "https://example.com/img".to_string(),
            text: None,
        };
        let json = serde_json::to_string(&link).unwrap();
        let back: LinkEntry = serde_json::from_str(&json).unwrap();
        assert!(back.text.is_none());
    }

    #[test]
    fn link_entry_from_json_null_text() {
        let v = json!({"href": "https://x.com", "text": null});
        let link: LinkEntry = serde_json::from_value(v).unwrap();
        assert!(link.text.is_none());
    }

    #[test]
    fn link_entry_clone_and_debug() {
        let link = LinkEntry {
            href: "https://x.com".to_string(),
            text: Some("X".to_string()),
        };
        let cloned = link.clone();
        assert_eq!(cloned.href, "https://x.com");
        let dbg = format!("{link:?}");
        assert!(dbg.contains("LinkEntry"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LinksResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn links_result_roundtrip() {
        let result = LinksResult {
            links: vec![
                LinkEntry {
                    href: "https://example.com/a".to_string(),
                    text: Some("A".to_string()),
                },
                LinkEntry {
                    href: "https://example.com/b".to_string(),
                    text: None,
                },
            ],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: LinksResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.links.len(), 2);
        assert_eq!(back.links[0].href, "https://example.com/a");
        assert!(back.links[1].text.is_none());
    }

    #[test]
    fn links_result_empty() {
        let result = LinksResult { links: vec![] };
        let json = serde_json::to_string(&result).unwrap();
        let back: LinksResult = serde_json::from_str(&json).unwrap();
        assert!(back.links.is_empty());
    }

    #[test]
    fn links_result_from_json() {
        let v = json!({"links": [{"href": "https://x.com", "text": "X"}]});
        let result: LinksResult = serde_json::from_value(v).unwrap();
        assert_eq!(result.links.len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ClickResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn click_result_roundtrip_clicked() {
        let result = ClickResult {
            clicked: true,
            navigation_url: Some("https://example.com/next".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ClickResult = serde_json::from_str(&json).unwrap();
        assert!(back.clicked);
        assert_eq!(
            back.navigation_url.as_deref(),
            Some("https://example.com/next")
        );
    }

    #[test]
    fn click_result_not_clicked() {
        let result = ClickResult {
            clicked: false,
            navigation_url: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ClickResult = serde_json::from_str(&json).unwrap();
        assert!(!back.clicked);
        assert!(back.navigation_url.is_none());
    }

    #[test]
    fn click_result_from_json_null_nav() {
        let v = json!({"clicked": true, "navigation_url": null});
        let result: ClickResult = serde_json::from_value(v).unwrap();
        assert!(result.clicked);
        assert!(result.navigation_url.is_none());
    }

    #[test]
    fn click_result_clone_and_debug() {
        let result = ClickResult {
            clicked: true,
            navigation_url: None,
        };
        let cloned = result.clone();
        assert!(cloned.clicked);
        let dbg = format!("{result:?}");
        assert!(dbg.contains("ClickResult"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FormResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn form_result_roundtrip() {
        let result = FormResult {
            filled_count: 3,
            submitted: Some(true),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: FormResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.filled_count, 3);
        assert_eq!(back.submitted, Some(true));
    }

    #[test]
    fn form_result_not_submitted() {
        let result = FormResult {
            filled_count: 1,
            submitted: Some(false),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: FormResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.submitted, Some(false));
    }

    #[test]
    fn form_result_submitted_none() {
        let result = FormResult {
            filled_count: 0,
            submitted: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: FormResult = serde_json::from_str(&json).unwrap();
        assert!(back.submitted.is_none());
    }

    #[test]
    fn form_result_zero_filled() {
        let result = FormResult {
            filled_count: 0,
            submitted: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: FormResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.filled_count, 0);
    }

    #[test]
    fn form_result_clone_and_debug() {
        let result = FormResult {
            filled_count: 5,
            submitted: Some(true),
        };
        let cloned = result.clone();
        assert_eq!(cloned.filled_count, 5);
        let dbg = format!("{result:?}");
        assert!(dbg.contains("FormResult"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // JsResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn js_result_roundtrip() {
        let result = JsResult {
            result: "42".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: JsResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.result, "42");
    }

    #[test]
    fn js_result_empty_string() {
        let result = JsResult {
            result: String::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: JsResult = serde_json::from_str(&json).unwrap();
        assert!(back.result.is_empty());
    }

    #[test]
    fn js_result_json_string_value() {
        // JS eval might return a JSON string
        let result = JsResult {
            result: r#"{"key": "value"}"#.to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: JsResult = serde_json::from_str(&json).unwrap();
        assert!(back.result.contains("key"));
    }

    #[test]
    fn js_result_clone_and_debug() {
        let result = JsResult {
            result: "test".to_string(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.result, "test");
        let dbg = format!("{result:?}");
        assert!(dbg.contains("JsResult"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cookie
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cookie_full_roundtrip() {
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
        assert_eq!(back.value, "abc123");
        assert_eq!(back.domain.as_deref(), Some(".example.com"));
        assert_eq!(back.path.as_deref(), Some("/"));
        assert_eq!(back.expires, Some(1_700_000_000.0));
        assert!(back.http_only.unwrap());
        assert!(back.secure.unwrap());
        assert_eq!(back.same_site.as_deref(), Some("Lax"));
    }

    #[test]
    fn cookie_minimal_all_none() {
        let cookie = Cookie {
            name: "id".to_string(),
            value: "v".to_string(),
            domain: None,
            path: None,
            expires: None,
            http_only: None,
            secure: None,
            same_site: None,
        };
        let json = serde_json::to_string(&cookie).unwrap();
        let back: Cookie = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "id");
        assert!(back.domain.is_none());
        assert!(back.path.is_none());
        assert!(back.expires.is_none());
        assert!(back.http_only.is_none());
        assert!(back.secure.is_none());
        assert!(back.same_site.is_none());
    }

    #[test]
    fn cookie_from_json_with_nulls() {
        let v = json!({
            "name": "sid",
            "value": "xyz",
            "domain": null,
            "path": null,
            "expires": null,
            "http_only": null,
            "secure": null,
            "same_site": null
        });
        let cookie: Cookie = serde_json::from_value(v).unwrap();
        assert_eq!(cookie.name, "sid");
        assert!(cookie.domain.is_none());
        assert!(cookie.http_only.is_none());
    }

    #[test]
    fn cookie_secure_false() {
        let cookie = Cookie {
            name: "debug".to_string(),
            value: "1".to_string(),
            domain: None,
            path: None,
            expires: None,
            http_only: Some(false),
            secure: Some(false),
            same_site: None,
        };
        let json = serde_json::to_string(&cookie).unwrap();
        let back: Cookie = serde_json::from_str(&json).unwrap();
        assert!(!back.http_only.unwrap());
        assert!(!back.secure.unwrap());
    }

    #[test]
    fn cookie_same_site_strict() {
        let cookie = Cookie {
            name: "csrf".to_string(),
            value: "tok".to_string(),
            domain: None,
            path: None,
            expires: None,
            http_only: None,
            secure: None,
            same_site: Some("Strict".to_string()),
        };
        let json = serde_json::to_string(&cookie).unwrap();
        let back: Cookie = serde_json::from_str(&json).unwrap();
        assert_eq!(back.same_site.as_deref(), Some("Strict"));
    }

    #[test]
    fn cookie_same_site_none_value() {
        let cookie = Cookie {
            name: "cross".to_string(),
            value: "x".to_string(),
            domain: None,
            path: None,
            expires: None,
            http_only: None,
            secure: Some(true),
            same_site: Some("None".to_string()),
        };
        let json = serde_json::to_string(&cookie).unwrap();
        let back: Cookie = serde_json::from_str(&json).unwrap();
        assert_eq!(back.same_site.as_deref(), Some("None"));
    }

    #[test]
    fn cookie_expires_zero() {
        let cookie = Cookie {
            name: "expired".to_string(),
            value: "x".to_string(),
            domain: None,
            path: None,
            expires: Some(0.0),
            http_only: None,
            secure: None,
            same_site: None,
        };
        let json = serde_json::to_string(&cookie).unwrap();
        let back: Cookie = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expires, Some(0.0));
    }

    #[test]
    fn cookie_clone_and_debug() {
        let cookie = Cookie {
            name: "a".to_string(),
            value: "b".to_string(),
            domain: None,
            path: None,
            expires: None,
            http_only: None,
            secure: None,
            same_site: None,
        };
        let cloned = cookie.clone();
        assert_eq!(cloned.name, "a");
        let dbg = format!("{cookie:?}");
        assert!(dbg.contains("Cookie"));
    }

    #[test]
    fn cookie_serialized_includes_null_optionals() {
        // Without skip_serializing_if, None fields serialize as null
        let cookie = Cookie {
            name: "x".to_string(),
            value: "y".to_string(),
            domain: None,
            path: None,
            expires: None,
            http_only: None,
            secure: None,
            same_site: None,
        };
        let json_str = serde_json::to_string(&cookie).unwrap();
        // Since there's no skip_serializing_if on Cookie fields,
        // the None fields should appear as null in the JSON
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(v.get("domain").is_some());
        assert!(v["domain"].is_null());
        assert!(v["path"].is_null());
        assert!(v["expires"].is_null());
        assert!(v["http_only"].is_null());
        assert!(v["secure"].is_null());
        assert!(v["same_site"].is_null());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProxyConfig
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn proxy_config_roundtrip() {
        let config = ProxyConfig {
            server: "http://proxy:8080".to_string(),
            bypass_list: Some(vec!["localhost".to_string(), "127.0.0.1".to_string()]),
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.server, "http://proxy:8080");
        assert_eq!(back.bypass_list.as_ref().unwrap().len(), 2);
        assert_eq!(back.username.as_deref(), Some("user"));
        assert_eq!(back.password.as_deref(), Some("pass"));
    }

    #[test]
    fn proxy_config_minimal() {
        let config = ProxyConfig {
            server: "socks5://proxy:1080".to_string(),
            bypass_list: None,
            username: None,
            password: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.server, "socks5://proxy:1080");
        assert!(back.bypass_list.is_none());
        assert!(back.username.is_none());
        assert!(back.password.is_none());
    }

    #[test]
    fn proxy_config_empty_bypass_list() {
        let config = ProxyConfig {
            server: "http://proxy:8080".to_string(),
            bypass_list: Some(vec![]),
            username: None,
            password: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert!(back.bypass_list.unwrap().is_empty());
    }

    #[test]
    fn proxy_config_from_json_with_nulls() {
        let v = json!({
            "server": "http://p:8080",
            "bypass_list": null,
            "username": null,
            "password": null
        });
        let config: ProxyConfig = serde_json::from_value(v).unwrap();
        assert_eq!(config.server, "http://p:8080");
        assert!(config.bypass_list.is_none());
    }

    #[test]
    fn proxy_config_clone_and_debug() {
        let config = ProxyConfig {
            server: "http://p:8080".to_string(),
            bypass_list: None,
            username: None,
            password: None,
        };
        let cloned = config.clone();
        assert_eq!(cloned.server, config.server);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ProxyConfig"));
    }

    #[test]
    fn proxy_config_serialized_includes_null_optionals() {
        let config = ProxyConfig {
            server: "http://p:80".to_string(),
            bypass_list: None,
            username: None,
            password: None,
        };
        let json_str = serde_json::to_string(&config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(v["bypass_list"].is_null());
        assert!(v["username"].is_null());
        assert!(v["password"].is_null());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProxyResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn proxy_result_roundtrip_enabled() {
        let result = ProxyResult {
            enabled: true,
            mode: "fixed_servers".to_string(),
            server: Some("http://proxy:8080".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ProxyResult = serde_json::from_str(&json).unwrap();
        assert!(back.enabled);
        assert_eq!(back.mode, "fixed_servers");
        assert_eq!(back.server.as_deref(), Some("http://proxy:8080"));
    }

    #[test]
    fn proxy_result_disabled() {
        let result = ProxyResult {
            enabled: false,
            mode: "direct".to_string(),
            server: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ProxyResult = serde_json::from_str(&json).unwrap();
        assert!(!back.enabled);
        assert_eq!(back.mode, "direct");
        assert!(back.server.is_none());
    }

    #[test]
    fn proxy_result_clone_and_debug() {
        let result = ProxyResult {
            enabled: true,
            mode: "pac".to_string(),
            server: None,
        };
        let cloned = result.clone();
        assert!(cloned.enabled);
        let dbg = format!("{result:?}");
        assert!(dbg.contains("ProxyResult"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WaitResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn wait_result_roundtrip_found() {
        let result = WaitResult { found: true };
        let json = serde_json::to_string(&result).unwrap();
        let back: WaitResult = serde_json::from_str(&json).unwrap();
        assert!(back.found);
    }

    #[test]
    fn wait_result_not_found() {
        let result = WaitResult { found: false };
        let json = serde_json::to_string(&result).unwrap();
        let back: WaitResult = serde_json::from_str(&json).unwrap();
        assert!(!back.found);
    }

    #[test]
    fn wait_result_from_json() {
        let v = json!({"found": true});
        let result: WaitResult = serde_json::from_value(v).unwrap();
        assert!(result.found);
    }

    #[test]
    fn wait_result_clone_and_debug() {
        let result = WaitResult { found: true };
        let cloned = result.clone();
        assert!(cloned.found);
        let dbg = format!("{result:?}");
        assert!(dbg.contains("WaitResult"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ApiErrorResponse
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn api_error_response_full() {
        let json = json!({"error": {"message": "timeout", "code": "TIMEOUT"}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert_eq!(detail.message.as_deref(), Some("timeout"));
        assert_eq!(detail.code.as_deref(), Some("TIMEOUT"));
    }

    #[test]
    fn api_error_response_no_error() {
        let json = json!({"error": null});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error.is_none());
    }

    #[test]
    fn api_error_response_missing_error_key() {
        // serde deserializes missing Option fields as None
        let json = json!({});
        let result: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(result.error.is_none());
    }

    #[test]
    fn api_error_detail_partial() {
        let json = json!({"error": {"message": "something went wrong"}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert_eq!(detail.message.as_deref(), Some("something went wrong"));
        assert!(detail.code.is_none());
    }

    #[test]
    fn api_error_detail_code_only() {
        let json = json!({"error": {"code": "ERR_404"}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert!(detail.message.is_none());
        assert_eq!(detail.code.as_deref(), Some("ERR_404"));
    }

    #[test]
    fn api_error_detail_all_null() {
        let json = json!({"error": {"message": null, "code": null}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert!(detail.message.is_none());
        assert!(detail.code.is_none());
    }

    #[test]
    fn api_error_detail_empty_object() {
        let json = json!({"error": {}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert!(detail.message.is_none());
        assert!(detail.code.is_none());
    }

    #[test]
    fn api_error_response_clone_and_debug() {
        let err = ApiErrorResponse {
            error: Some(ApiErrorDetail {
                message: Some("test".to_string()),
                code: None,
            }),
        };
        let cloned = err.clone();
        assert!(cloned.error.is_some());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_detail_clone_and_debug() {
        let detail = ApiErrorDetail {
            message: Some("err".to_string()),
            code: Some("E001".to_string()),
        };
        let cloned = detail.clone();
        assert_eq!(cloned.message.as_deref(), Some("err"));
        let dbg = format!("{detail:?}");
        assert!(dbg.contains("ApiErrorDetail"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cross-type JSON deserialization edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn navigate_result_rejects_wrong_status_type() {
        let v = json!({"url": "https://x.com", "status": "200", "title": null});
        let result = serde_json::from_value::<NavigateResult>(v);
        assert!(result.is_err());
    }

    #[test]
    fn screenshot_result_rejects_missing_field() {
        let v = json!({"image_data": "x", "width": 100});
        let result = serde_json::from_value::<ScreenshotResult>(v);
        assert!(result.is_err());
    }

    #[test]
    fn pdf_result_rejects_missing_field() {
        let v = json!({"pdf_data": "x"});
        let result = serde_json::from_value::<PdfResult>(v);
        assert!(result.is_err());
    }

    #[test]
    fn click_result_rejects_missing_clicked() {
        let v = json!({"navigation_url": null});
        let result = serde_json::from_value::<ClickResult>(v);
        assert!(result.is_err());
    }

    #[test]
    fn form_result_rejects_missing_filled_count() {
        let v = json!({"submitted": true});
        let result = serde_json::from_value::<FormResult>(v);
        assert!(result.is_err());
    }

    #[test]
    fn js_result_rejects_missing_result() {
        let v = json!({});
        let result = serde_json::from_value::<JsResult>(v);
        assert!(result.is_err());
    }

    #[test]
    fn wait_result_rejects_missing_found() {
        let v = json!({});
        let result = serde_json::from_value::<WaitResult>(v);
        assert!(result.is_err());
    }

    #[test]
    fn cookie_rejects_missing_required_name() {
        let v = json!({"value": "x"});
        let result = serde_json::from_value::<Cookie>(v);
        assert!(result.is_err());
    }

    #[test]
    fn cookie_rejects_missing_required_value() {
        let v = json!({"name": "x"});
        let result = serde_json::from_value::<Cookie>(v);
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Unicode and special characters
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn navigate_result_unicode_title() {
        let result = NavigateResult {
            url: "https://example.jp".to_string(),
            status: 200,
            title: Some("日本語のタイトル".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: NavigateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title.as_deref(), Some("日本語のタイトル"));
    }

    #[test]
    fn text_result_unicode_content() {
        let result = TextResult {
            text: "Héllo wörld! 🌍".to_string(),
            word_count: Some(2),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TextResult = serde_json::from_str(&json).unwrap();
        assert!(back.text.contains("🌍"));
    }

    #[test]
    fn js_result_with_escaped_chars() {
        let result = JsResult {
            result: "line1\nline2\ttab".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: JsResult = serde_json::from_str(&json).unwrap();
        assert!(back.result.contains('\n'));
        assert!(back.result.contains('\t'));
    }

    #[test]
    fn link_entry_with_special_url_chars() {
        let link = LinkEntry {
            href: "https://example.com/search?q=hello+world&lang=en".to_string(),
            text: Some("Search \"hello\"".to_string()),
        };
        let json = serde_json::to_string(&link).unwrap();
        let back: LinkEntry = serde_json::from_str(&json).unwrap();
        assert!(back.href.contains("q=hello+world"));
        assert!(back.text.unwrap().contains("\"hello\""));
    }

    #[test]
    fn cookie_with_special_value() {
        let cookie = Cookie {
            name: "data".to_string(),
            value: "a=b&c=d;e=f".to_string(),
            domain: None,
            path: None,
            expires: None,
            http_only: None,
            secure: None,
            same_site: None,
        };
        let json = serde_json::to_string(&cookie).unwrap();
        let back: Cookie = serde_json::from_str(&json).unwrap();
        assert_eq!(back.value, "a=b&c=d;e=f");
    }
}
