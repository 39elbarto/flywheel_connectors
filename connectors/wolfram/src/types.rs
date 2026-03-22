//! Wolfram Alpha API types.

use serde::{Deserialize, Serialize};

/// Configuration for the Wolfram Alpha connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolframConfig {
    /// Wolfram Alpha App ID (credential reference for secretless mode).
    pub credential_id: fcp_core::CredentialId,

    /// Base URL override (for testing).
    #[serde(default = "default_base_url")]
    pub base_url: String,

    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_base_url() -> String {
    "api.wolframalpha.com".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
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
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        }))
        .expect("parse config");
        assert_eq!(config.base_url, "api.wolframalpha.com");
        assert_eq!(config.timeout_ms, 30_000);
    }

    #[test]
    fn config_custom_base_url() {
        let config: WolframConfig = serde_json::from_value(serde_json::json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "base_url": "test.example.com",
            "timeout_ms": 5000
        }))
        .expect("parse config");
        assert_eq!(config.base_url, "test.example.com");
        assert_eq!(config.timeout_ms, 5000);
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
