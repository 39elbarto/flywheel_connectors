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
