//! HTTP client for the Google Places API (New).

use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{Value, json};
use tracing::debug;

use crate::error::{GooglePlacesError, GooglePlacesResult};
use crate::types::GooglePlacesConfig;

#[derive(Debug, Clone)]
pub struct GooglePlacesClient {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    default_field_mask: Option<String>,
}

impl GooglePlacesClient {
    pub fn from_config(config: &GooglePlacesConfig) -> GooglePlacesResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms))
            .build()?;
        Ok(Self {
            client,
            base_url: config.normalized_base_url(),
            api_key: config.api_key.clone(),
            default_field_mask: config.default_field_mask.clone(),
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn default_headers(&self, field_mask: Option<&str>) -> GooglePlacesResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Goog-Api-Key",
            HeaderValue::from_str(&self.api_key)
                .map_err(|error| GooglePlacesError::Config(error.to_string()))?,
        );
        if let Some(mask) = field_mask.or(self.default_field_mask.as_deref()) {
            headers.insert(
                "X-Goog-FieldMask",
                HeaderValue::from_str(mask)
                    .map_err(|error| GooglePlacesError::Config(error.to_string()))?,
            );
        }
        Ok(headers)
    }

    async fn decode_response(response: reqwest::Response) -> GooglePlacesResult<Value> {
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(GooglePlacesError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(serde_json::from_str(&body)?)
    }

    pub async fn search_text(
        &self,
        query: &str,
        max_result_count: Option<u32>,
        open_now: Option<bool>,
        field_mask: Option<&str>,
    ) -> GooglePlacesResult<Value> {
        if query.trim().is_empty() {
            return Err(GooglePlacesError::Config("query must not be empty".into()));
        }
        let url = format!("{}/v1/places:searchText", self.base_url);
        let mut body = json!({ "textQuery": query });
        if let Some(max_result_count) = max_result_count {
            body["maxResultCount"] = json!(max_result_count);
        }
        if let Some(open_now) = open_now {
            body["openNow"] = json!(open_now);
        }
        debug!(url = %url, query, "Google Places text search");
        let response = self
            .client
            .post(url)
            .headers(self.default_headers(field_mask)?)
            .json(&body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn autocomplete(
        &self,
        input: &str,
        session_token: Option<&str>,
        field_mask: Option<&str>,
    ) -> GooglePlacesResult<Value> {
        if input.trim().is_empty() {
            return Err(GooglePlacesError::Config("input must not be empty".into()));
        }
        let url = format!("{}/v1/places:autocomplete", self.base_url);
        let mut body = json!({ "input": input });
        if let Some(session_token) = session_token {
            body["sessionToken"] = json!(session_token);
        }
        let response = self
            .client
            .post(url)
            .headers(self.default_headers(field_mask)?)
            .json(&body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn get_place(
        &self,
        place: &str,
        language_code: Option<&str>,
        field_mask: Option<&str>,
    ) -> GooglePlacesResult<Value> {
        if place.trim().is_empty() {
            return Err(GooglePlacesError::Config("place must not be empty".into()));
        }
        let place = place.trim_start_matches('/');
        let url = format!("{}/v1/{}", self.base_url, place);
        let mut request = self
            .client
            .get(url)
            .headers(self.default_headers(field_mask)?);
        if let Some(language_code) = language_code {
            request = request.query(&[("languageCode", language_code)]);
        }
        let response = request.send().await?;
        Self::decode_response(response).await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[fcp_async_core::runtime::test]
    async fn text_search_uses_expected_endpoint_and_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "places": [
                    {
                        "id": "abc",
                        "displayName": { "text": "Coffee Shop" },
                        "formattedAddress": "123 Main St"
                    }
                ]
            })))
            .mount(&server)
            .await;

        let config = GooglePlacesConfig::from_value(json!({
            "api_key": "test-key",
            "base_url": server.uri(),
            "default_field_mask": "places.id,places.displayName,places.formattedAddress"
        }))
        .expect("config should parse");
        let client = GooglePlacesClient::from_config(&config).expect("client should build");
        let result = client
            .search_text("coffee", Some(3), Some(true), None)
            .await
            .expect("search should succeed");
        let requests = server
            .received_requests()
            .await
            .expect("request recording should be enabled");
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, reqwest::Method::POST);
        assert_eq!(request.url.path(), "/v1/places:searchText");
        assert_eq!(
            request
                .headers
                .get("x-goog-api-key")
                .and_then(|value| value.to_str().ok()),
            Some("test-key")
        );
        assert_eq!(
            request
                .headers
                .get("x-goog-fieldmask")
                .and_then(|value| value.to_str().ok()),
            Some("places.id,places.displayName,places.formattedAddress")
        );
        assert_eq!(
            request
                .body_json::<Value>()
                .expect("request body should be valid JSON"),
            json!({
                "textQuery": "coffee",
                "maxResultCount": 3,
                "openNow": true
            })
        );
        assert_eq!(result["places"][0]["id"], "abc");
    }

    #[fcp_async_core::runtime::test]
    async fn get_place_uses_trimmed_resource_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/places/abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "abc123",
                "displayName": { "text": "Cafe" }
            })))
            .mount(&server)
            .await;

        let config = GooglePlacesConfig::from_value(json!({
            "api_key": "test-key",
            "base_url": server.uri()
        }))
        .expect("config should parse");
        let client = GooglePlacesClient::from_config(&config).expect("client should build");
        let result = client
            .get_place("/places/abc123", None, Some("id,displayName"))
            .await
            .expect("details should succeed");
        assert_eq!(result["id"], "abc123");
    }
}
