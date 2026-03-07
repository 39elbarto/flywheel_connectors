//! `Salesforce` API client.

use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SalesforceError, SalesforceResult},
    types::ApiErrorResponse,
};

/// Default `Salesforce` instance URL.
pub const DEFAULT_BASE_URL: &str = "https://login.salesforce.com";

/// API version path prefix for the `Salesforce` REST API.
pub const API_PATH: &str = "/services/data/v59.0";

/// Authentication mode for the `Salesforce` API.
#[derive(Clone)]
pub enum SalesforceAuth {
    /// `OAuth2` Bearer access token.
    AccessToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl SalesforceAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::AccessToken(_) => "access_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for SalesforceAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessToken(_) => f.debug_tuple("AccessToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Salesforce` API client.
pub struct SalesforceClient {
    client: Client,
    auth: SalesforceAuth,
    base_url: String,
}

impl fmt::Debug for SalesforceClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalesforceClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl SalesforceClient {
    /// Create a new `Salesforce` client.
    pub fn new(auth: SalesforceAuth, base_url: Option<&str>) -> SalesforceResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-salesforce/0.1.0")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    /// Create a new client with a custom reqwest client (for testing).
    pub fn with_client(client: Client, auth: SalesforceAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            SalesforceAuth::AccessToken(token) => req.bearer_auth(token),
            SalesforceAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> SalesforceResult<serde_json::Value> {
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
    ) -> SalesforceResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Salesforce can return either an array of errors or a single message object.
        let detail = serde_json::from_str::<Vec<crate::types::ApiErrorItem>>(&body)
            .ok()
            .and_then(|items| items.first().and_then(|e| e.message.clone()))
            .or_else(|| {
                serde_json::from_str::<ApiErrorResponse>(&body)
                    .ok()
                    .and_then(|e| {
                        e.message
                            .or_else(|| e.errors.first().and_then(|i| i.message.clone()))
                    })
            })
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(SalesforceError::Unauthorized),
            403 => Err(SalesforceError::Forbidden),
            404 => Err(SalesforceError::NotFound { resource: detail }),
            429 => Err(SalesforceError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SalesforceError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// GET request to the `Salesforce` API.
    #[instrument(skip(self), fields(url))]
    pub async fn get(&self, path: &str) -> SalesforceResult<serde_json::Value> {
        let url = format!("{}{API_PATH}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// POST request to the `Salesforce` API.
    #[instrument(skip(self, body), fields(url))]
    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        let url = format!("{}{API_PATH}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self.add_auth(self.client.post(&url).json(body));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// DELETE request to the `Salesforce` API.
    #[instrument(skip(self), fields(url))]
    pub async fn delete(&self, path: &str) -> SalesforceResult<serde_json::Value> {
        let url = format!("{}{API_PATH}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self.add_auth(self.client.delete(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Accounts --

    /// Get a single account by ID.
    pub async fn get_account(
        &self,
        account_id: &str,
        fields: Option<&[String]>,
    ) -> SalesforceResult<serde_json::Value> {
        let qs = fields.map_or_else(String::new, |f| format!("?fields={}", f.join(",")));
        self.get(&format!("/sobjects/Account/{account_id}{qs}"))
            .await
    }

    /// Query accounts via SOQL.
    pub async fn list_accounts(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
    ) -> SalesforceResult<serde_json::Value> {
        let cols = fields.map_or_else(|| "Id, Name, Industry".to_string(), |f| f.join(", "));
        let mut query = format!("SELECT {cols} FROM Account");
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    // -- Contacts --

    /// Query contacts via SOQL.
    pub async fn list_contacts(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
        account_id: Option<&str>,
    ) -> SalesforceResult<serde_json::Value> {
        let cols = fields.map_or_else(
            || "Id, FirstName, LastName, Email".to_string(),
            |f| f.join(", "),
        );
        let mut query = format!("SELECT {cols} FROM Contact");
        if let Some(aid) = account_id {
            let _ = write!(query, " WHERE AccountId = '{aid}'");
        }
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    /// Create a contact.
    pub async fn create_contact(
        &self,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        self.post("/sobjects/Contact", body).await
    }

    /// Delete a contact.
    pub async fn delete_contact(&self, contact_id: &str) -> SalesforceResult<serde_json::Value> {
        self.delete(&format!("/sobjects/Contact/{contact_id}"))
            .await
    }

    // -- Leads --

    /// Query leads via SOQL.
    pub async fn list_leads(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
        status: Option<&str>,
    ) -> SalesforceResult<serde_json::Value> {
        let cols = fields.map_or_else(
            || "Id, FirstName, LastName, Company, Status".to_string(),
            |f| f.join(", "),
        );
        let mut query = format!("SELECT {cols} FROM Lead");
        if let Some(s) = status {
            let _ = write!(query, " WHERE Status = '{s}'");
        }
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    /// Convert a lead via the actions endpoint.
    pub async fn convert_lead(
        &self,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        self.post("/actions/standard/convertLead", body).await
    }

    // -- Opportunities --

    /// Query opportunities via SOQL.
    pub async fn list_opportunities(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
        stage: Option<&str>,
    ) -> SalesforceResult<serde_json::Value> {
        let cols = fields.map_or_else(
            || "Id, Name, StageName, Amount, CloseDate".to_string(),
            |f| f.join(", "),
        );
        let mut query = format!("SELECT {cols} FROM Opportunity");
        if let Some(s) = stage {
            let _ = write!(query, " WHERE StageName = '{s}'");
        }
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    /// Create an opportunity.
    pub async fn create_opportunity(
        &self,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        self.post("/sobjects/Opportunity", body).await
    }

    // -- Cases --

    /// Query cases via SOQL.
    pub async fn list_cases(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
        status: Option<&str>,
    ) -> SalesforceResult<serde_json::Value> {
        let cols = fields.map_or_else(
            || "Id, Subject, Status, Priority".to_string(),
            |f| f.join(", "),
        );
        let mut query = format!("SELECT {cols} FROM Case");
        if let Some(s) = status {
            let _ = write!(query, " WHERE Status = '{s}'");
        }
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    /// Create a case.
    pub async fn create_case(
        &self,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        self.post("/sobjects/Case", body).await
    }

    // -- SOQL --

    /// Execute a raw SOQL query.
    pub async fn soql_query(&self, query: &str) -> SalesforceResult<serde_json::Value> {
        let encoded = urlencoding_encode(query);
        self.get(&format!("/query?q={encoded}")).await
    }

    // -- Reports --

    /// Get a report by ID.
    pub async fn get_report(
        &self,
        report_id: &str,
        include_details: bool,
    ) -> SalesforceResult<serde_json::Value> {
        let qs = if include_details {
            "?includeDetails=true"
        } else {
            ""
        };
        self.get(&format!("/analytics/reports/{report_id}{qs}"))
            .await
    }
}

/// Minimal URL-encoding for SOQL query strings.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                let _ = write!(out, "{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = SalesforceAuth::AccessToken("00Dxx0000001secret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("00Dxx0000001secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = SalesforceAuth::AccessToken("tok".into());
        assert!(!token.is_secretless());

        let cred = SalesforceAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = SalesforceAuth::AccessToken("tok".into());
        assert_eq!(token.redacted_label(), "access_token:redacted");

        let cred = SalesforceAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn urlencoding_basic() {
        assert_eq!(
            urlencoding_encode("SELECT Id FROM Account"),
            "SELECT+Id+FROM+Account"
        );
    }

    #[test]
    fn urlencoding_special_chars() {
        let encoded = urlencoding_encode("WHERE Name = 'Acme'");
        assert!(encoded.contains("%27"));
        assert!(encoded.contains('+'));
    }

    // -- Additional client tests --

    #[test]
    fn client_new_default_url() {
        let client =
            SalesforceClient::new(SalesforceAuth::AccessToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SalesforceClient::new(
            SalesforceAuth::AccessToken("tok".into()),
            Some("https://myorg.salesforce.com/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://myorg.salesforce.com");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = SalesforceClient::new(
            SalesforceAuth::AccessToken("tok".into()),
            Some("https://example.com/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn client_with_client_trims_slash() {
        let inner = Client::builder().build().unwrap();
        let client = SalesforceClient::with_client(
            inner,
            SalesforceAuth::AccessToken("tok".into()),
            "https://x.com/",
        );
        assert_eq!(client.base_url, "https://x.com");
    }

    #[test]
    fn client_debug_redacts_token() {
        let client = SalesforceClient::new(
            SalesforceAuth::AccessToken("super_secret_token_123".into()),
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super_secret_token_123"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("SalesforceClient"));
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_debug_shows_credential_id() {
        let cred = CredentialId::new();
        let cred_str = cred.to_string();
        let client = SalesforceClient::new(SalesforceAuth::CredentialId(cred), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(&cred_str));
    }

    #[test]
    fn auth_clone() {
        let auth = SalesforceAuth::AccessToken("tok".into());
        let cloned = auth.clone();
        assert!(!auth.is_secretless());
        assert_eq!(cloned.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn auth_credential_debug_shows_id() {
        let cred = CredentialId::new();
        let cred_str = cred.to_string();
        let auth = SalesforceAuth::CredentialId(cred);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains(&cred_str));
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn urlencoding_empty_string() {
        assert_eq!(urlencoding_encode(""), "");
    }

    #[test]
    fn urlencoding_unreserved_chars_pass_through() {
        let input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
        assert_eq!(urlencoding_encode(input), input);
    }

    #[test]
    fn urlencoding_percent_encoded() {
        let encoded = urlencoding_encode("a=b&c=d");
        assert!(encoded.contains("%3D"));
        assert!(encoded.contains("%26"));
    }

    #[test]
    fn urlencoding_slash_encoded() {
        let encoded = urlencoding_encode("/path/to");
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://login.salesforce.com");
    }

    #[test]
    fn api_path_value() {
        assert_eq!(API_PATH, "/services/data/v59.0");
    }
}
