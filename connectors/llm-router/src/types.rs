//! LLM Router types.

use serde::{Deserialize, Serialize};

/// Routing strategy for provider selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingStrategy {
    /// Select the cheapest provider for the request.
    Cost,
    /// Select the provider with lowest recent latency.
    Latency,
    /// Select the most capable provider for the task.
    Capability,
    /// Try providers in configured order until one succeeds.
    Fallback,
}

impl Default for RoutingStrategy {
    fn default() -> Self {
        Self::Cost
    }
}

impl RoutingStrategy {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "cost" => Some(Self::Cost),
            "latency" => Some(Self::Latency),
            "capability" => Some(Self::Capability),
            "fallback" => Some(Self::Fallback),
            _ => None,
        }
    }
}

/// Health status of a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderStatus {
    Healthy,
    Degraded,
    Unavailable,
}

/// Model capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    Vision,
    ToolUse,
    LongContext,
    Code,
    Math,
    Streaming,
}

impl ModelCapability {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "vision" => Some(Self::Vision),
            "tool_use" => Some(Self::ToolUse),
            "long_context" => Some(Self::LongContext),
            "code" => Some(Self::Code),
            "math" => Some(Self::Math),
            "streaming" => Some(Self::Streaming),
            _ => None,
        }
    }
}

/// Budget enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BudgetEnforcement {
    Hard,
    Soft,
    None,
}

impl Default for BudgetEnforcement {
    fn default() -> Self {
        Self::None
    }
}

/// Provider authentication mode.
#[derive(Debug, Clone)]
pub enum ProviderAuth {
    /// Direct API key (secrets in memory).
    ApiKey(String),
    /// Secretless via egress proxy credential injection.
    CredentialId(String),
}

impl ProviderAuth {
    pub fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }

    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(key) => {
                if key.len() > 8 {
                    format!("api_key:{}...{}", &key[..4], &key[key.len() - 4..])
                } else {
                    "api_key:****".into()
                }
            }
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }
}

/// Configuration for a single provider backend.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub base_url: String,
    pub auth: ProviderAuth,
    pub models: Vec<ModelInfo>,
    pub priority: u32,
}

/// Per-provider provisioning readiness.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderReadiness {
    pub name: String,
    pub auth_ok: bool,
    pub auth_mode: String,
    pub network_ok: bool,
    pub models_ok: bool,
    pub model_count: usize,
}

/// Information about a model available from a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub capabilities: Vec<ModelCapability>,
    pub context_window: u32,
    pub cost_per_input_token: f64,
    pub cost_per_output_token: f64,
}

/// Budget configuration.
#[derive(Debug, Clone)]
pub struct BudgetConfig {
    pub budget_usd: f64,
    pub enforcement: BudgetEnforcement,
    pub period: String,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            budget_usd: f64::INFINITY,
            enforcement: BudgetEnforcement::None,
            period: "session".into(),
        }
    }
}

/// Routing decision metadata.
#[derive(Debug, Clone, Serialize)]
pub struct RoutingDecision {
    pub strategy_used: String,
    pub candidates_evaluated: u32,
    pub fallback_used: bool,
    pub reason: String,
}

/// Per-provider usage tracking.
#[derive(Debug, Default, Clone)]
pub struct ProviderUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub requests: u64,
    pub errors: u64,
    pub total_latency_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- RoutingStrategy ----

    #[test]
    fn routing_strategy_default_is_cost() {
        assert_eq!(RoutingStrategy::default(), RoutingStrategy::Cost);
    }

    #[test]
    fn routing_strategy_from_str_opt_all_variants() {
        assert_eq!(
            RoutingStrategy::from_str_opt("cost"),
            Some(RoutingStrategy::Cost)
        );
        assert_eq!(
            RoutingStrategy::from_str_opt("latency"),
            Some(RoutingStrategy::Latency)
        );
        assert_eq!(
            RoutingStrategy::from_str_opt("capability"),
            Some(RoutingStrategy::Capability)
        );
        assert_eq!(
            RoutingStrategy::from_str_opt("fallback"),
            Some(RoutingStrategy::Fallback)
        );
    }

    #[test]
    fn routing_strategy_from_str_opt_invalid() {
        assert_eq!(RoutingStrategy::from_str_opt(""), None);
        assert_eq!(RoutingStrategy::from_str_opt("Cost"), None);
        assert_eq!(RoutingStrategy::from_str_opt("LATENCY"), None);
        assert_eq!(RoutingStrategy::from_str_opt("random"), None);
    }

    #[test]
    fn routing_strategy_serde_roundtrip() {
        for strategy in [
            RoutingStrategy::Cost,
            RoutingStrategy::Latency,
            RoutingStrategy::Capability,
            RoutingStrategy::Fallback,
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            let back: RoutingStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(back, strategy);
        }
    }

    #[test]
    fn routing_strategy_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&RoutingStrategy::Cost).unwrap(),
            "\"cost\""
        );
        assert_eq!(
            serde_json::to_string(&RoutingStrategy::Latency).unwrap(),
            "\"latency\""
        );
        assert_eq!(
            serde_json::to_string(&RoutingStrategy::Capability).unwrap(),
            "\"capability\""
        );
        assert_eq!(
            serde_json::to_string(&RoutingStrategy::Fallback).unwrap(),
            "\"fallback\""
        );
    }

    // ---- ProviderStatus ----

    #[test]
    fn provider_status_serde_roundtrip() {
        for status in [
            ProviderStatus::Healthy,
            ProviderStatus::Degraded,
            ProviderStatus::Unavailable,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: ProviderStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn provider_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&ProviderStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&ProviderStatus::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&ProviderStatus::Unavailable).unwrap(),
            "\"unavailable\""
        );
    }

    // ---- ModelCapability ----

    #[test]
    fn model_capability_from_str_opt_all_variants() {
        assert_eq!(
            ModelCapability::from_str_opt("vision"),
            Some(ModelCapability::Vision)
        );
        assert_eq!(
            ModelCapability::from_str_opt("tool_use"),
            Some(ModelCapability::ToolUse)
        );
        assert_eq!(
            ModelCapability::from_str_opt("long_context"),
            Some(ModelCapability::LongContext)
        );
        assert_eq!(
            ModelCapability::from_str_opt("code"),
            Some(ModelCapability::Code)
        );
        assert_eq!(
            ModelCapability::from_str_opt("math"),
            Some(ModelCapability::Math)
        );
        assert_eq!(
            ModelCapability::from_str_opt("streaming"),
            Some(ModelCapability::Streaming)
        );
    }

    #[test]
    fn model_capability_from_str_opt_invalid() {
        assert_eq!(ModelCapability::from_str_opt(""), None);
        assert_eq!(ModelCapability::from_str_opt("Vision"), None);
        assert_eq!(ModelCapability::from_str_opt("tool-use"), None);
        assert_eq!(ModelCapability::from_str_opt("unknown"), None);
    }

    #[test]
    fn model_capability_serde_roundtrip() {
        for cap in [
            ModelCapability::Vision,
            ModelCapability::ToolUse,
            ModelCapability::LongContext,
            ModelCapability::Code,
            ModelCapability::Math,
            ModelCapability::Streaming,
        ] {
            let json = serde_json::to_string(&cap).unwrap();
            let back: ModelCapability = serde_json::from_str(&json).unwrap();
            assert_eq!(back, cap);
        }
    }

    #[test]
    fn model_capability_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&ModelCapability::ToolUse).unwrap(),
            "\"tool_use\""
        );
        assert_eq!(
            serde_json::to_string(&ModelCapability::LongContext).unwrap(),
            "\"long_context\""
        );
    }

    // ---- BudgetEnforcement ----

    #[test]
    fn budget_enforcement_default_is_none() {
        assert_eq!(BudgetEnforcement::default(), BudgetEnforcement::None);
    }

    #[test]
    fn budget_enforcement_serde_roundtrip() {
        for enforcement in [
            BudgetEnforcement::Hard,
            BudgetEnforcement::Soft,
            BudgetEnforcement::None,
        ] {
            let json = serde_json::to_string(&enforcement).unwrap();
            let back: BudgetEnforcement = serde_json::from_str(&json).unwrap();
            assert_eq!(back, enforcement);
        }
    }

    // ---- ProviderAuth ----

    #[test]
    fn provider_auth_is_secretless() {
        assert!(!ProviderAuth::ApiKey("sk-test".into()).is_secretless());
        assert!(ProviderAuth::CredentialId("my-cred".into()).is_secretless());
    }

    #[test]
    fn provider_auth_redacted_label_long_key() {
        let auth = ProviderAuth::ApiKey("sk-1234567890abcdef".into());
        let label = auth.redacted_label();
        assert!(label.starts_with("api_key:sk-1"));
        assert!(label.contains("..."));
        assert!(label.ends_with("cdef"));
        // Must not contain the full key
        assert!(!label.contains("1234567890abcdef"));
    }

    #[test]
    fn provider_auth_redacted_label_short_key() {
        let auth = ProviderAuth::ApiKey("short".into());
        let label = auth.redacted_label();
        assert_eq!(label, "api_key:****");
    }

    #[test]
    fn provider_auth_redacted_label_credential_id() {
        let auth = ProviderAuth::CredentialId("my-uuid-123".into());
        assert_eq!(auth.redacted_label(), "credential_id:my-uuid-123");
    }

    // ---- BudgetConfig ----

    #[test]
    fn budget_config_default() {
        let config = BudgetConfig::default();
        assert!(config.budget_usd.is_infinite());
        assert_eq!(config.enforcement, BudgetEnforcement::None);
        assert_eq!(config.period, "session");
    }

    // ---- ModelInfo ----

    #[test]
    fn model_info_serde_roundtrip() {
        let model = ModelInfo {
            id: "gpt-4o".into(),
            capabilities: vec![ModelCapability::Vision, ModelCapability::Code],
            context_window: 128_000,
            cost_per_input_token: 0.000005,
            cost_per_output_token: 0.000015,
        };

        let json = serde_json::to_string(&model).unwrap();
        let back: ModelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "gpt-4o");
        assert_eq!(back.capabilities.len(), 2);
        assert_eq!(back.context_window, 128_000);
    }

    // ---- ProviderUsage ----

    #[test]
    fn provider_usage_default_is_zero() {
        let usage = ProviderUsage::default();
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.output_tokens, 0);
        assert_eq!(usage.cost_usd, 0.0);
        assert_eq!(usage.requests, 0);
        assert_eq!(usage.errors, 0);
        assert_eq!(usage.total_latency_ms, 0);
    }

    // ---- RoutingDecision ----

    #[test]
    fn routing_decision_serializes() {
        let decision = RoutingDecision {
            strategy_used: "cost".into(),
            candidates_evaluated: 3,
            fallback_used: false,
            reason: "cheapest".into(),
        };
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["strategy_used"], "cost");
        assert_eq!(json["candidates_evaluated"], 3);
        assert_eq!(json["fallback_used"], false);
    }

    // ---- ProviderReadiness ----

    #[test]
    fn provider_readiness_serializes() {
        let readiness = ProviderReadiness {
            name: "anthropic".into(),
            auth_ok: true,
            auth_mode: "api_key".into(),
            network_ok: true,
            models_ok: true,
            model_count: 2,
        };
        let json = serde_json::to_value(&readiness).unwrap();
        assert_eq!(json["name"], "anthropic");
        assert_eq!(json["auth_ok"], true);
        assert_eq!(json["model_count"], 2);
    }
}
