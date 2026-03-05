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

    // ---- RoutingStrategy: Clone, Copy, PartialEq, Eq, Debug ----

    #[test]
    fn routing_strategy_clone() {
        let original = RoutingStrategy::Latency;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn routing_strategy_copy() {
        let a = RoutingStrategy::Capability;
        let b = a; // Copy, not move
        assert_eq!(a, b);
    }

    #[test]
    fn routing_strategy_eq_all_variants() {
        assert_eq!(RoutingStrategy::Cost, RoutingStrategy::Cost);
        assert_eq!(RoutingStrategy::Latency, RoutingStrategy::Latency);
        assert_eq!(RoutingStrategy::Capability, RoutingStrategy::Capability);
        assert_eq!(RoutingStrategy::Fallback, RoutingStrategy::Fallback);
        assert_ne!(RoutingStrategy::Cost, RoutingStrategy::Latency);
        assert_ne!(RoutingStrategy::Capability, RoutingStrategy::Fallback);
    }

    #[test]
    fn routing_strategy_debug() {
        assert_eq!(format!("{:?}", RoutingStrategy::Cost), "Cost");
        assert_eq!(format!("{:?}", RoutingStrategy::Latency), "Latency");
        assert_eq!(format!("{:?}", RoutingStrategy::Capability), "Capability");
        assert_eq!(format!("{:?}", RoutingStrategy::Fallback), "Fallback");
    }

    // ---- ProviderStatus: Clone, Copy, PartialEq, Eq, Debug, deserialize ----

    #[test]
    fn provider_status_clone() {
        let original = ProviderStatus::Degraded;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn provider_status_copy() {
        let a = ProviderStatus::Healthy;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn provider_status_eq_and_ne() {
        assert_eq!(ProviderStatus::Healthy, ProviderStatus::Healthy);
        assert_ne!(ProviderStatus::Healthy, ProviderStatus::Degraded);
        assert_ne!(ProviderStatus::Degraded, ProviderStatus::Unavailable);
    }

    #[test]
    fn provider_status_debug() {
        assert_eq!(format!("{:?}", ProviderStatus::Healthy), "Healthy");
        assert_eq!(format!("{:?}", ProviderStatus::Degraded), "Degraded");
        assert_eq!(
            format!("{:?}", ProviderStatus::Unavailable),
            "Unavailable"
        );
    }

    #[test]
    fn provider_status_deserialize_from_lowercase() {
        let h: ProviderStatus = serde_json::from_str("\"healthy\"").unwrap();
        assert_eq!(h, ProviderStatus::Healthy);
        let d: ProviderStatus = serde_json::from_str("\"degraded\"").unwrap();
        assert_eq!(d, ProviderStatus::Degraded);
        let u: ProviderStatus = serde_json::from_str("\"unavailable\"").unwrap();
        assert_eq!(u, ProviderStatus::Unavailable);
    }

    // ---- ModelCapability: Clone, Copy, Hash, Debug, Eq, deserialize ----

    #[test]
    fn model_capability_clone() {
        let original = ModelCapability::Vision;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn model_capability_copy() {
        let a = ModelCapability::Code;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn model_capability_hash_in_hashset() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ModelCapability::Vision);
        set.insert(ModelCapability::Code);
        set.insert(ModelCapability::Vision); // duplicate
        assert_eq!(set.len(), 2);
        assert!(set.contains(&ModelCapability::Vision));
        assert!(set.contains(&ModelCapability::Code));
        assert!(!set.contains(&ModelCapability::Math));
    }

    #[test]
    fn model_capability_debug() {
        assert_eq!(format!("{:?}", ModelCapability::Vision), "Vision");
        assert_eq!(format!("{:?}", ModelCapability::ToolUse), "ToolUse");
        assert_eq!(
            format!("{:?}", ModelCapability::LongContext),
            "LongContext"
        );
        assert_eq!(format!("{:?}", ModelCapability::Streaming), "Streaming");
    }

    #[test]
    fn model_capability_eq() {
        assert_eq!(ModelCapability::Math, ModelCapability::Math);
        assert_ne!(ModelCapability::Math, ModelCapability::Code);
    }

    #[test]
    fn model_capability_deserialize_snake_case() {
        let tu: ModelCapability = serde_json::from_str("\"tool_use\"").unwrap();
        assert_eq!(tu, ModelCapability::ToolUse);
        let lc: ModelCapability =
            serde_json::from_str("\"long_context\"").unwrap();
        assert_eq!(lc, ModelCapability::LongContext);
        let v: ModelCapability = serde_json::from_str("\"vision\"").unwrap();
        assert_eq!(v, ModelCapability::Vision);
    }

    // ---- BudgetEnforcement: Clone, Copy, serialize lowercase, Debug ----

    #[test]
    fn budget_enforcement_clone() {
        let original = BudgetEnforcement::Hard;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn budget_enforcement_copy() {
        let a = BudgetEnforcement::Soft;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn budget_enforcement_serialize_lowercase() {
        assert_eq!(
            serde_json::to_string(&BudgetEnforcement::Hard).unwrap(),
            "\"hard\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetEnforcement::Soft).unwrap(),
            "\"soft\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetEnforcement::None).unwrap(),
            "\"none\""
        );
    }

    #[test]
    fn budget_enforcement_debug() {
        assert_eq!(format!("{:?}", BudgetEnforcement::Hard), "Hard");
        assert_eq!(format!("{:?}", BudgetEnforcement::Soft), "Soft");
        assert_eq!(format!("{:?}", BudgetEnforcement::None), "None");
    }

    // ---- ProviderAuth: Clone, Debug, edge cases ----

    #[test]
    fn provider_auth_clone() {
        let auth = ProviderAuth::ApiKey("sk-secret".into());
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), auth.redacted_label());
    }

    #[test]
    fn provider_auth_debug_does_not_hide_key() {
        // Debug derive shows internal data (not redacted)
        let auth = ProviderAuth::ApiKey("sk-mysecretkey".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiKey"));
    }

    #[test]
    fn provider_auth_redacted_label_exact_8_char_key() {
        // Exactly 8 chars: not > 8, so should be masked
        let auth = ProviderAuth::ApiKey("12345678".into());
        assert_eq!(auth.redacted_label(), "api_key:****");
    }

    #[test]
    fn provider_auth_redacted_label_9_char_key() {
        // 9 chars: > 8, so should show first 4 and last 4
        let auth = ProviderAuth::ApiKey("123456789".into());
        assert_eq!(auth.redacted_label(), "api_key:1234...6789");
    }

    #[test]
    fn provider_auth_redacted_label_empty_key() {
        let auth = ProviderAuth::ApiKey(String::new());
        assert_eq!(auth.redacted_label(), "api_key:****");
    }

    #[test]
    fn provider_auth_redacted_label_empty_credential_id() {
        let auth = ProviderAuth::CredentialId(String::new());
        assert_eq!(auth.redacted_label(), "credential_id:");
    }

    // ---- ProviderConfig: Clone, Debug, empty models ----

    #[test]
    fn provider_config_clone() {
        let config = ProviderConfig {
            name: "openai".into(),
            base_url: "https://api.openai.com".into(),
            auth: ProviderAuth::ApiKey("sk-test-123456789".into()),
            models: vec![],
            priority: 1,
        };
        let cloned = config.clone();
        assert_eq!(cloned.name, "openai");
        assert_eq!(cloned.priority, 1);
    }

    #[test]
    fn provider_config_debug() {
        let config = ProviderConfig {
            name: "anthropic".into(),
            base_url: "https://api.anthropic.com".into(),
            auth: ProviderAuth::CredentialId("cred-1".into()),
            models: vec![],
            priority: 2,
        };
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ProviderConfig"));
        assert!(dbg.contains("anthropic"));
        assert!(dbg.contains("priority: 2"));
    }

    #[test]
    fn provider_config_empty_models() {
        let config = ProviderConfig {
            name: "test".into(),
            base_url: "http://localhost".into(),
            auth: ProviderAuth::ApiKey("key123456789".into()),
            models: vec![],
            priority: 0,
        };
        assert!(config.models.is_empty());
        assert_eq!(config.priority, 0);
    }

    // ---- ProviderReadiness: Clone, Debug, all-false ----

    #[test]
    fn provider_readiness_clone() {
        let readiness = ProviderReadiness {
            name: "test".into(),
            auth_ok: true,
            auth_mode: "credential_id".into(),
            network_ok: true,
            models_ok: true,
            model_count: 5,
        };
        let cloned = readiness.clone();
        assert_eq!(cloned.name, "test");
        assert_eq!(cloned.model_count, 5);
    }

    #[test]
    fn provider_readiness_debug() {
        let readiness = ProviderReadiness {
            name: "openai".into(),
            auth_ok: false,
            auth_mode: "api_key".into(),
            network_ok: true,
            models_ok: false,
            model_count: 0,
        };
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProviderReadiness"));
        assert!(dbg.contains("openai"));
    }

    #[test]
    fn provider_readiness_all_false() {
        let readiness = ProviderReadiness {
            name: "broken".into(),
            auth_ok: false,
            auth_mode: "none".into(),
            network_ok: false,
            models_ok: false,
            model_count: 0,
        };
        let json = serde_json::to_value(&readiness).unwrap();
        assert_eq!(json["auth_ok"], false);
        assert_eq!(json["network_ok"], false);
        assert_eq!(json["models_ok"], false);
        assert_eq!(json["model_count"], 0);
    }

    // ---- ModelInfo: Clone, Debug, empty capabilities, zero costs ----

    #[test]
    fn model_info_clone() {
        let model = ModelInfo {
            id: "claude-3".into(),
            capabilities: vec![ModelCapability::Vision],
            context_window: 200_000,
            cost_per_input_token: 0.000003,
            cost_per_output_token: 0.000015,
        };
        let cloned = model.clone();
        assert_eq!(cloned.id, "claude-3");
        assert_eq!(cloned.capabilities.len(), 1);
    }

    #[test]
    fn model_info_debug() {
        let model = ModelInfo {
            id: "gpt-4".into(),
            capabilities: vec![],
            context_window: 8192,
            cost_per_input_token: 0.00003,
            cost_per_output_token: 0.00006,
        };
        let dbg = format!("{model:?}");
        assert!(dbg.contains("ModelInfo"));
        assert!(dbg.contains("gpt-4"));
    }

    #[test]
    fn model_info_empty_capabilities() {
        let model = ModelInfo {
            id: "basic-model".into(),
            capabilities: vec![],
            context_window: 4096,
            cost_per_input_token: 0.0001,
            cost_per_output_token: 0.0002,
        };
        let json = serde_json::to_value(&model).unwrap();
        assert_eq!(json["capabilities"], serde_json::json!([]));
    }

    #[test]
    fn model_info_zero_costs() {
        let model = ModelInfo {
            id: "free-model".into(),
            capabilities: vec![ModelCapability::Code],
            context_window: 2048,
            cost_per_input_token: 0.0,
            cost_per_output_token: 0.0,
        };
        assert_eq!(model.cost_per_input_token, 0.0);
        assert_eq!(model.cost_per_output_token, 0.0);
    }

    // ---- BudgetConfig: Clone, Debug, custom values ----

    #[test]
    fn budget_config_clone() {
        let config = BudgetConfig {
            budget_usd: 50.0,
            enforcement: BudgetEnforcement::Hard,
            period: "monthly".into(),
        };
        let cloned = config.clone();
        assert_eq!(cloned.budget_usd, 50.0);
        assert_eq!(cloned.enforcement, BudgetEnforcement::Hard);
        assert_eq!(cloned.period, "monthly");
    }

    #[test]
    fn budget_config_debug() {
        let config = BudgetConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("BudgetConfig"));
        assert!(dbg.contains("session"));
    }

    #[test]
    fn budget_config_custom_values() {
        let config = BudgetConfig {
            budget_usd: 1000.0,
            enforcement: BudgetEnforcement::Soft,
            period: "daily".into(),
        };
        assert_eq!(config.budget_usd, 1000.0);
        assert_eq!(config.enforcement, BudgetEnforcement::Soft);
        assert_eq!(config.period, "daily");
    }

    // ---- RoutingDecision: Clone, Debug, fallback_used true ----

    #[test]
    fn routing_decision_clone() {
        let decision = RoutingDecision {
            strategy_used: "latency".into(),
            candidates_evaluated: 5,
            fallback_used: false,
            reason: "lowest p50".into(),
        };
        let cloned = decision.clone();
        assert_eq!(cloned.strategy_used, "latency");
        assert_eq!(cloned.candidates_evaluated, 5);
    }

    #[test]
    fn routing_decision_debug() {
        let decision = RoutingDecision {
            strategy_used: "cost".into(),
            candidates_evaluated: 2,
            fallback_used: true,
            reason: "primary failed".into(),
        };
        let dbg = format!("{decision:?}");
        assert!(dbg.contains("RoutingDecision"));
        assert!(dbg.contains("cost"));
        assert!(dbg.contains("primary failed"));
    }

    #[test]
    fn routing_decision_fallback_used_true() {
        let decision = RoutingDecision {
            strategy_used: "fallback".into(),
            candidates_evaluated: 3,
            fallback_used: true,
            reason: "primary and secondary unavailable".into(),
        };
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["fallback_used"], true);
        assert_eq!(json["strategy_used"], "fallback");
        assert_eq!(json["candidates_evaluated"], 3);
    }

    // ---- ProviderUsage: Clone, Debug, accumulation ----

    #[test]
    fn provider_usage_clone() {
        let mut usage = ProviderUsage::default();
        usage.requests = 10;
        usage.cost_usd = 0.5;
        let cloned = usage.clone();
        assert_eq!(cloned.requests, 10);
        assert_eq!(cloned.cost_usd, 0.5);
    }

    #[test]
    fn provider_usage_debug() {
        let usage = ProviderUsage::default();
        let dbg = format!("{usage:?}");
        assert!(dbg.contains("ProviderUsage"));
        assert!(dbg.contains("input_tokens: 0"));
    }

    #[test]
    fn provider_usage_accumulation() {
        let mut usage = ProviderUsage::default();

        // Simulate 3 requests
        usage.input_tokens += 1000;
        usage.output_tokens += 500;
        usage.cost_usd += 0.01;
        usage.requests += 1;
        usage.total_latency_ms += 200;

        usage.input_tokens += 2000;
        usage.output_tokens += 1000;
        usage.cost_usd += 0.02;
        usage.requests += 1;
        usage.total_latency_ms += 150;

        usage.input_tokens += 500;
        usage.output_tokens += 250;
        usage.cost_usd += 0.005;
        usage.requests += 1;
        usage.errors += 1;
        usage.total_latency_ms += 5000; // slow/errored

        assert_eq!(usage.input_tokens, 3500);
        assert_eq!(usage.output_tokens, 1750);
        assert!((usage.cost_usd - 0.035).abs() < 1e-10);
        assert_eq!(usage.requests, 3);
        assert_eq!(usage.errors, 1);
        assert_eq!(usage.total_latency_ms, 5350);
    }
}
