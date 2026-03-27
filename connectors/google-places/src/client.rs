//! `HTTP` client for the `Google Places API (New)`.

use reqwest::header::{HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::json;
use tracing::debug;

use crate::error::{GooglePlacesError, GooglePlacesResult};
use crate::types::{
    AutocompleteInput, AutocompleteResponse, GetPlaceInput, GooglePlacesConfig, PlaceRecord,
    SearchTextInput, SearchTextResponse,
};

#[derive(Clone)]
pub struct GooglePlacesClient {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    search_text_field_mask: String,
    autocomplete_field_mask: String,
    place_details_field_mask: String,
}

impl std::fmt::Debug for GooglePlacesClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GooglePlacesClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("search_text_field_mask", &self.search_text_field_mask)
            .field("autocomplete_field_mask", &self.autocomplete_field_mask)
            .field("place_details_field_mask", &self.place_details_field_mask)
            .finish_non_exhaustive()
    }
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
            search_text_field_mask: config.search_text_field_mask.clone(),
            autocomplete_field_mask: config.autocomplete_field_mask.clone(),
            place_details_field_mask: config.place_details_field_mask.clone(),
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn headers_with_mask(&self, field_mask: &str) -> GooglePlacesResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Goog-Api-Key",
            HeaderValue::from_str(&self.api_key)
                .map_err(|error| GooglePlacesError::Config(error.to_string()))?,
        );
        headers.insert(
            "X-Goog-FieldMask",
            HeaderValue::from_str(field_mask)
                .map_err(|error| GooglePlacesError::Config(error.to_string()))?,
        );
        Ok(headers)
    }

    fn resolve_field_mask<'a>(
        override_mask: Option<&'a str>,
        default_mask: &'a str,
        field_name: &str,
    ) -> GooglePlacesResult<&'a str> {
        let mask = override_mask.unwrap_or(default_mask).trim();
        if mask.is_empty() {
            return Err(GooglePlacesError::Config(format!(
                "{field_name} must not be empty"
            )));
        }
        Ok(mask)
    }

    async fn decode_response<T: DeserializeOwned>(
        response: reqwest::Response,
    ) -> GooglePlacesResult<T> {
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
        input: &SearchTextInput,
    ) -> GooglePlacesResult<SearchTextResponse> {
        let url = format!("{}/v1/places:searchText", self.base_url);
        let field_mask = Self::resolve_field_mask(
            input.field_mask.as_deref(),
            &self.search_text_field_mask,
            "search_text field mask",
        )?;
        let mut body = json!({ "textQuery": input.query.as_str() });
        if let Some(max_result_count) = input.max_result_count {
            body["maxResultCount"] = json!(max_result_count);
        }
        if let Some(open_now) = input.open_now {
            body["openNow"] = json!(open_now);
        }
        debug!(url = %url, query = %input.query, "Google Places text search");
        let response = self
            .client
            .post(url)
            .headers(self.headers_with_mask(field_mask)?)
            .json(&body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn autocomplete(
        &self,
        input: &AutocompleteInput,
    ) -> GooglePlacesResult<AutocompleteResponse> {
        let url = format!("{}/v1/places:autocomplete", self.base_url);
        let field_mask = Self::resolve_field_mask(
            input.field_mask.as_deref(),
            &self.autocomplete_field_mask,
            "autocomplete field mask",
        )?;
        let mut body = json!({ "input": input.input.as_str() });
        if let Some(session_token) = &input.session_token {
            body["sessionToken"] = json!(session_token);
        }
        let response = self
            .client
            .post(url)
            .headers(self.headers_with_mask(field_mask)?)
            .json(&body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn get_place(&self, input: &GetPlaceInput) -> GooglePlacesResult<PlaceRecord> {
        let field_mask = Self::resolve_field_mask(
            input.field_mask.as_deref(),
            &self.place_details_field_mask,
            "place_details field mask",
        )?;
        let place = input.place.trim_start_matches('/');
        let url = format!("{}/v1/{}", self.base_url, place);
        let mut request = self
            .client
            .get(url)
            .headers(self.headers_with_mask(field_mask)?);
        if let Some(language_code) = input.language_code.as_deref() {
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
            "base_url": server.uri()
        }))
        .expect("config should parse");
        let client = GooglePlacesClient::from_config(&config).expect("client should build");
        let input = SearchTextInput::from_value(json!({
            "query": "coffee",
            "max_result_count": 3,
            "open_now": true
        }))
        .expect("input should parse");
        let result = client
            .search_text(&input)
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
            Some(config.search_text_field_mask.as_str())
        );
        assert_eq!(
            request
                .body_json::<serde_json::Value>()
                .expect("request body should be valid JSON"),
            json!({
                "textQuery": "coffee",
                "maxResultCount": 3,
                "openNow": true
            })
        );
        assert_eq!(result.places[0].id.as_deref(), Some("abc"));
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
        let input = GetPlaceInput::from_value(json!({
            "place": "/places/abc123",
            "language_code": "en"
        }))
        .expect("input should parse");
        let result = client
            .get_place(&input)
            .await
            .expect("details should succeed");
        assert_eq!(result.id.as_deref(), Some("abc123"));
    }

    #[fcp_async_core::runtime::test]
    async fn autocomplete_uses_session_token_and_default_mask() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/places:autocomplete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "suggestions": [
                    {
                        "placePrediction": {
                            "place": "places/abc123",
                            "placeId": "abc123",
                            "text": { "text": "Coffee Shop" }
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let config = GooglePlacesConfig::from_value(json!({
            "api_key": "test-key",
            "base_url": server.uri()
        }))
        .expect("config should parse");
        let client = GooglePlacesClient::from_config(&config).expect("client should build");
        let input = AutocompleteInput::from_value(json!({
            "input": "coffee sh",
            "session_token": "session-123"
        }))
        .expect("input should parse");
        let result = client
            .autocomplete(&input)
            .await
            .expect("autocomplete should succeed");
        let requests = server
            .received_requests()
            .await
            .expect("request recording should be enabled");
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(
            request
                .headers
                .get("x-goog-fieldmask")
                .and_then(|value| value.to_str().ok()),
            Some(config.autocomplete_field_mask.as_str())
        );
        assert_eq!(
            request
                .body_json::<serde_json::Value>()
                .expect("request body should be valid JSON"),
            json!({
                "input": "coffee sh",
                "sessionToken": "session-123"
            })
        );
        assert_eq!(
            result.suggestions[0]
                .place_prediction
                .as_ref()
                .and_then(|prediction| prediction.place.as_deref()),
            Some("places/abc123")
        );
    }
}
