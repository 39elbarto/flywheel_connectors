//! Configuration and typed operation models for the `Google Places` connector.

use std::collections::BTreeMap;

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use url::Url;

pub const DEFAULT_SEARCH_TEXT_FIELD_MASK: &str =
    "places.id,places.name,places.displayName,places.formattedAddress";
pub const DEFAULT_AUTOCOMPLETE_FIELD_MASK: &str =
    "suggestions.placePrediction.place,suggestions.placePrediction.placeId,suggestions.placePrediction.text.text,suggestions.queryPrediction.text.text";
pub const DEFAULT_PLACE_DETAILS_FIELD_MASK: &str =
    "id,name,displayName,formattedAddress,types,googleMapsUri";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GooglePlacesConfig {
    pub api_key: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_search_text_field_mask")]
    pub search_text_field_mask: String,
    #[serde(default = "default_autocomplete_field_mask")]
    pub autocomplete_field_mask: String,
    #[serde(default = "default_place_details_field_mask")]
    pub place_details_field_mask: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchTextInput {
    pub query: String,
    #[serde(default)]
    pub max_result_count: Option<u32>,
    #[serde(default)]
    pub open_now: Option<bool>,
    #[serde(default)]
    pub field_mask: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutocompleteInput {
    pub input: String,
    #[serde(default)]
    pub session_token: Option<String>,
    #[serde(default)]
    pub field_mask: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetPlaceInput {
    pub place: String,
    #[serde(default)]
    pub language_code: Option<String>,
    #[serde(default)]
    pub field_mask: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedText {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub language_code: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct PlaceRecord {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub display_name: Option<LocalizedText>,
    #[serde(default)]
    pub formatted_address: Option<String>,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub google_maps_uri: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SearchTextResponse {
    #[serde(default)]
    pub places: Vec<PlaceRecord>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SuggestionText {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct PlacePrediction {
    #[serde(default)]
    pub place: Option<String>,
    #[serde(default)]
    pub place_id: Option<String>,
    #[serde(default)]
    pub text: Option<SuggestionText>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct QueryPrediction {
    #[serde(default)]
    pub text: Option<SuggestionText>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AutocompleteSuggestion {
    #[serde(default)]
    pub place_prediction: Option<PlacePrediction>,
    #[serde(default)]
    pub query_prediction: Option<QueryPrediction>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AutocompleteResponse {
    #[serde(default)]
    pub suggestions: Vec<AutocompleteSuggestion>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

const fn default_request_timeout_ms() -> u64 {
    15_000
}

fn default_base_url() -> String {
    "https://places.googleapis.com".to_string()
}

fn default_search_text_field_mask() -> String {
    DEFAULT_SEARCH_TEXT_FIELD_MASK.to_string()
}

fn default_autocomplete_field_mask() -> String {
    DEFAULT_AUTOCOMPLETE_FIELD_MASK.to_string()
}

fn default_place_details_field_mask() -> String {
    DEFAULT_PLACE_DETAILS_FIELD_MASK.to_string()
}

fn invalid_request(code: u32, message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code,
        message: message.into(),
    }
}

fn parse_value<T: DeserializeOwned>(value: Value, code: u32, context: &str) -> FcpResult<T> {
    serde_json::from_value(value)
        .map_err(|error| invalid_request(code, format!("Invalid {context}: {error}")))
}

fn validate_non_empty_mask(mask: &str, field: &str, code: u32) -> FcpResult<()> {
    if mask.trim().is_empty() {
        return Err(invalid_request(code, format!("{field} must not be empty")));
    }
    Ok(())
}

impl GooglePlacesConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self = parse_value(value, 1003, "Google Places config")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.api_key.trim().is_empty() {
            return Err(invalid_request(1003, "api_key must not be empty"));
        }
        if self.request_timeout_ms == 0 {
            return Err(invalid_request(
                1003,
                "request_timeout_ms must be greater than zero",
            ));
        }
        validate_non_empty_mask(&self.search_text_field_mask, "search_text_field_mask", 1003)?;
        validate_non_empty_mask(
            &self.autocomplete_field_mask,
            "autocomplete_field_mask",
            1003,
        )?;
        validate_non_empty_mask(
            &self.place_details_field_mask,
            "place_details_field_mask",
            1003,
        )?;
        let parsed = Url::parse(self.base_url.trim())
            .map_err(|error| invalid_request(1003, format!("Invalid base_url: {error}")))?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(invalid_request(1003, "base_url must use http or https"));
        }
        Ok(())
    }

    #[must_use]
    pub fn normalized_base_url(&self) -> String {
        self.base_url.trim().trim_end_matches('/').to_string()
    }
}

impl SearchTextInput {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let input: Self = parse_value(value, 1005, "google_places.search_text input")?;
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.query.trim().is_empty() {
            return Err(invalid_request(1005, "query must not be empty"));
        }
        if let Some(field_mask) = &self.field_mask {
            validate_non_empty_mask(field_mask, "field_mask", 1005)?;
        }
        Ok(())
    }
}

impl AutocompleteInput {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let input: Self = parse_value(value, 1005, "google_places.autocomplete input")?;
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.input.trim().is_empty() {
            return Err(invalid_request(1005, "input must not be empty"));
        }
        if let Some(field_mask) = &self.field_mask {
            validate_non_empty_mask(field_mask, "field_mask", 1005)?;
        }
        Ok(())
    }
}

impl GetPlaceInput {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let input: Self = parse_value(value, 1005, "google_places.get_place input")?;
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.place.trim().is_empty() {
            return Err(invalid_request(1005, "place must not be empty"));
        }
        if let Some(field_mask) = &self.field_mask {
            validate_non_empty_mask(field_mask, "field_mask", 1005)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn config_parses_normalizes_and_applies_default_masks() {
        let config = GooglePlacesConfig::from_value(json!({
            "api_key": "abc",
            "base_url": "https://places.googleapis.com/"
        }))
        .expect("config should parse");
        assert_eq!(
            config.normalized_base_url(),
            "https://places.googleapis.com"
        );
        assert_eq!(config.search_text_field_mask, DEFAULT_SEARCH_TEXT_FIELD_MASK);
        assert_eq!(config.autocomplete_field_mask, DEFAULT_AUTOCOMPLETE_FIELD_MASK);
        assert_eq!(
            config.place_details_field_mask,
            DEFAULT_PLACE_DETAILS_FIELD_MASK
        );
    }

    #[test]
    fn config_rejects_blank_api_key() {
        let error = GooglePlacesConfig::from_value(json!({
            "api_key": " "
        }))
        .expect_err("blank api key must fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_rejects_blank_operation_field_mask() {
        let error = GooglePlacesConfig::from_value(json!({
            "api_key": "abc",
            "search_text_field_mask": "   "
        }))
        .expect_err("blank search field mask must fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn search_text_input_rejects_blank_query() {
        let error = SearchTextInput::from_value(json!({
            "query": "   "
        }))
        .expect_err("blank query must fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn autocomplete_response_deserializes_typed_predictions() {
        let response: AutocompleteResponse = serde_json::from_value(json!({
            "suggestions": [
                {
                    "placePrediction": {
                        "place": "places/abc123",
                        "placeId": "abc123",
                        "text": { "text": "Coffee Shop" }
                    }
                }
            ]
        }))
        .expect("response should deserialize");
        assert_eq!(response.suggestions.len(), 1);
        assert_eq!(
            response.suggestions[0]
                .place_prediction
                .as_ref()
                .and_then(|prediction| prediction.place.as_deref()),
            Some("places/abc123")
        );
    }

    #[test]
    fn search_text_response_preserves_extra_fields() {
        let response: SearchTextResponse = serde_json::from_value(json!({
            "places": [],
            "contextualContents": [{ "rank": 1 }]
        }))
        .expect("response should deserialize");
        assert!(response.extra.contains_key("contextualContents"));
    }
}
