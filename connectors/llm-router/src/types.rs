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
