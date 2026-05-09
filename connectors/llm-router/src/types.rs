//! LLM Router types.

use std::fmt;

use reqwest::header::{HeaderName, HeaderValue, InvalidHeaderValue};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

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
    Responses,
    Chat,
    Vision,
    ToolUse,
    LongContext,
    Code,
    Math,
    Streaming,
    Embeddings,
}

impl ModelCapability {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "responses" => Some(Self::Responses),
            "chat" => Some(Self::Chat),
            "vision" => Some(Self::Vision),
            "tool_use" => Some(Self::ToolUse),
            "long_context" => Some(Self::LongContext),
            "code" => Some(Self::Code),
            "math" => Some(Self::Math),
            "streaming" => Some(Self::Streaming),
            "embeddings" => Some(Self::Embeddings),
            _ => None,
        }
    }
}

/// Provider API family selected by the router for dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderApiFamily {
    Responses,
    Chat,
    Streaming,
    Embeddings,
}

impl ProviderApiFamily {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "responses" => Some(Self::Responses),
            "chat" | "chat_completions" => Some(Self::Chat),
            "streaming" | "chat_streaming" => Some(Self::Streaming),
            "embeddings" => Some(Self::Embeddings),
            _ => None,
        }
    }

    pub const fn capability(self) -> ModelCapability {
        match self {
            Self::Responses => ModelCapability::Responses,
            Self::Chat => ModelCapability::Chat,
            Self::Streaming => ModelCapability::Streaming,
            Self::Embeddings => ModelCapability::Embeddings,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Responses => "responses",
            Self::Chat => "chat",
            Self::Streaming => "streaming",
            Self::Embeddings => "embeddings",
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
#[derive(Clone)]
pub enum ProviderAuth {
    /// Direct API key (secrets in memory).
    ApiKey(String),
    /// Secretless via egress proxy credential injection.
    CredentialId(String),
}

impl fmt::Debug for ProviderAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"[REDACTED]").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

impl ProviderAuth {
    pub fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }

    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:[redacted]".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    pub fn bearer_authorization_header(&self) -> Result<Option<HeaderValue>, InvalidHeaderValue> {
        match self {
            Self::ApiKey(key) => HeaderValue::from_str(&format!("Bearer {key}")).map(Some),
            Self::CredentialId(_) => Ok(None),
        }
    }
}

/// Cloudflare AI Gateway header for authenticated gateway/BYOK traffic.
pub const CLOUDFLARE_AI_GATEWAY_AUTH_HEADER_NAME: &str = "cf-aig-authorization";

/// How an OpenAI-compatible API path is resolved against a provider base URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderApiPathMode {
    /// Append `/v1/<endpoint>` to a provider origin such as `https://api.openai.com`.
    AppendV1,
    /// Append `<endpoint>` directly because the base URL already includes `/v1/...`.
    OpenAiCompatibleBase,
}

/// Provider HTTP header containing secret material.
#[derive(Clone)]
pub struct ProviderHttpHeader {
    name: HeaderName,
    value: HeaderValue,
}

impl fmt::Debug for ProviderHttpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderHttpHeader")
            .field("name", &self.name.as_str())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl ProviderHttpHeader {
    pub fn bearer_secret(name: HeaderName, secret: &str) -> Result<Self, InvalidHeaderValue> {
        let value = HeaderValue::from_str(&format!("Bearer {secret}"))?;
        Ok(Self { name, value })
    }

    pub fn cloudflare_ai_gateway_authorization(secret: &str) -> Result<Self, InvalidHeaderValue> {
        Self::bearer_secret(
            HeaderName::from_static(CLOUDFLARE_AI_GATEWAY_AUTH_HEADER_NAME),
            secret,
        )
    }

    pub fn name(&self) -> &HeaderName {
        &self.name
    }

    pub fn value(&self) -> &HeaderValue {
        &self.value
    }

    pub fn redacted_label(&self) -> String {
        format!("{}:[redacted]", self.name.as_str())
    }
}

/// Authentication header a gateway provider may require beyond provider auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayAuthHeader {
    /// Standard OpenAI-compatible bearer token in the `Authorization` header.
    AuthorizationBearer,
    /// Cloudflare AI Gateway bearer token in the `cf-aig-authorization` header.
    CloudflareAiGatewayAuthorization,
}

/// Base URL strategy for an OpenAI-compatible gateway provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayEndpoint {
    /// Fixed OpenAI-compatible base URL owned by the gateway provider.
    FixedOpenAiCompatible {
        base_url: &'static str,
        host: &'static str,
        api_path_mode: ProviderApiPathMode,
    },
    /// Cloudflare AI Gateway URL built from account and gateway identifiers.
    CloudflareAiGateway {
        host: &'static str,
        provider_path: &'static str,
    },
    /// Operator-configured OpenAI-compatible gateway with no static host admission.
    OperatorConfiguredOpenAiCompatible,
    /// Microsoft Foundry `/openai/v1` endpoint on an Azure-owned resource host.
    MicrosoftFoundryOpenAiV1,
}

impl GatewayEndpoint {
    pub const fn static_host(self) -> Option<&'static str> {
        match self {
            Self::FixedOpenAiCompatible { host, .. } | Self::CloudflareAiGateway { host, .. } => {
                Some(host)
            }
            Self::OperatorConfiguredOpenAiCompatible | Self::MicrosoftFoundryOpenAiV1 => None,
        }
    }

    pub const fn fixed_base_url(self) -> Option<&'static str> {
        match self {
            Self::FixedOpenAiCompatible { base_url, .. } => Some(base_url),
            Self::CloudflareAiGateway { .. }
            | Self::OperatorConfiguredOpenAiCompatible
            | Self::MicrosoftFoundryOpenAiV1 => None,
        }
    }

    pub const fn api_path_mode(self) -> ProviderApiPathMode {
        match self {
            Self::FixedOpenAiCompatible { api_path_mode, .. } => api_path_mode,
            Self::CloudflareAiGateway { .. }
            | Self::OperatorConfiguredOpenAiCompatible
            | Self::MicrosoftFoundryOpenAiV1 => ProviderApiPathMode::OpenAiCompatibleBase,
        }
    }

    pub fn cloudflare_base_url(
        self,
        account_id: &str,
        gateway_id: &str,
    ) -> Result<String, GatewayDescriptorError> {
        let Self::CloudflareAiGateway {
            host,
            provider_path,
        } = self
        else {
            return Err(GatewayDescriptorError::WrongEndpointKind);
        };
        validate_gateway_path_segment("account_id", account_id)?;
        validate_gateway_path_segment("gateway_id", gateway_id)?;
        Ok(format!(
            "https://{host}/v1/{}/{}/{}",
            account_id.trim(),
            gateway_id.trim(),
            provider_path.trim_matches('/')
        ))
    }
}

/// Alias rewrite for gateway model identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayModelAlias {
    pub alias: &'static str,
    pub canonical: &'static str,
}

/// Metadata for one OpenAI-compatible gateway provider admitted by llm-router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayProviderDescriptor {
    pub id: &'static str,
    pub display_name: &'static str,
    pub auth_env_vars: &'static [&'static str],
    pub auth_choice_id: &'static str,
    pub endpoint: GatewayEndpoint,
    pub auth_headers: &'static [GatewayAuthHeader],
    pub aliases: &'static [GatewayModelAlias],
    pub passthrough_provider_models: bool,
    pub image_generation_provider: bool,
}

impl GatewayProviderDescriptor {
    pub fn normalize_model_id(&self, model_id: &str) -> String {
        let trimmed = model_id.trim();
        if trimmed.contains('/') {
            return trimmed.to_string();
        }

        let canonical = self
            .aliases
            .iter()
            .find(|alias| alias.alias == trimmed)
            .map_or(trimmed, |alias| alias.canonical);

        if canonical.starts_with("claude-") {
            format!("anthropic/{canonical}")
        } else {
            canonical.to_string()
        }
    }
}

/// Errors raised while validating gateway-provider descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GatewayDescriptorError {
    #[error("gateway provider descriptor has an empty id")]
    EmptyProviderId,
    #[error("duplicate gateway provider id: {0}")]
    DuplicateProviderId(String),
    #[error("gateway provider {provider_id} has no auth env vars")]
    MissingAuthEnvVars { provider_id: String },
    #[error("gateway provider {provider_id} has an empty auth env var")]
    EmptyAuthEnvVar { provider_id: String },
    #[error("gateway provider {provider_id} has an invalid fixed base URL: {reason}")]
    InvalidFixedBaseUrl { provider_id: String, reason: String },
    #[error("gateway provider {provider_id} has an empty alias")]
    EmptyAlias { provider_id: String },
    #[error("duplicate gateway model alias for {provider_id}: {alias}")]
    DuplicateAlias { provider_id: String, alias: String },
    #[error("{field} must contain only ASCII letters, digits, underscore, or dash")]
    InvalidPathSegment { field: &'static str },
    #[error("endpoint is not Cloudflare AI Gateway")]
    WrongEndpointKind,
}

const VERCEL_AI_GATEWAY_ALIASES: &[GatewayModelAlias] = &[
    GatewayModelAlias {
        alias: "opus-4.6",
        canonical: "claude-opus-4-6",
    },
    GatewayModelAlias {
        alias: "opus-4.5",
        canonical: "claude-opus-4-5",
    },
    GatewayModelAlias {
        alias: "sonnet-4.6",
        canonical: "claude-sonnet-4-6",
    },
    GatewayModelAlias {
        alias: "sonnet-4.5",
        canonical: "claude-sonnet-4-5",
    },
];

const XAI_ALIASES: &[GatewayModelAlias] = &[
    GatewayModelAlias {
        alias: "grok-4-fast-reasoning",
        canonical: "grok-4-fast",
    },
    GatewayModelAlias {
        alias: "grok-4-1-fast-reasoning",
        canonical: "grok-4-1-fast",
    },
    GatewayModelAlias {
        alias: "grok-4.20-experimental-beta-0304-reasoning",
        canonical: "grok-4.20-beta-latest-reasoning",
    },
    GatewayModelAlias {
        alias: "grok-4.20-experimental-beta-0304-non-reasoning",
        canonical: "grok-4.20-beta-latest-non-reasoning",
    },
    GatewayModelAlias {
        alias: "grok-4.20-reasoning",
        canonical: "grok-4.20-beta-latest-reasoning",
    },
    GatewayModelAlias {
        alias: "grok-4.20-non-reasoning",
        canonical: "grok-4.20-beta-latest-non-reasoning",
    },
];

const CLOUDFLARE_GATEWAY_AUTH_HEADERS: &[GatewayAuthHeader] = &[
    GatewayAuthHeader::AuthorizationBearer,
    GatewayAuthHeader::CloudflareAiGatewayAuthorization,
];

const STANDARD_BEARER_AUTH_HEADERS: &[GatewayAuthHeader] =
    &[GatewayAuthHeader::AuthorizationBearer];

const BUILT_IN_GATEWAY_PROVIDER_DESCRIPTORS: &[GatewayProviderDescriptor] = &[
    GatewayProviderDescriptor {
        id: "microsoft-foundry",
        display_name: "Microsoft Foundry",
        auth_env_vars: &["MICROSOFT_FOUNDRY_API_KEY", "AZURE_OPENAI_API_KEY"],
        auth_choice_id: "microsoft-foundry-credential",
        endpoint: GatewayEndpoint::MicrosoftFoundryOpenAiV1,
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: false,
        image_generation_provider: false,
    },
    GatewayProviderDescriptor {
        id: "cloudflare-ai-gateway",
        display_name: "Cloudflare AI Gateway",
        auth_env_vars: &["CLOUDFLARE_AI_GATEWAY_API_KEY"],
        auth_choice_id: "cloudflare-ai-gateway-api-key",
        endpoint: GatewayEndpoint::CloudflareAiGateway {
            host: "gateway.ai.cloudflare.com",
            provider_path: "openai",
        },
        auth_headers: CLOUDFLARE_GATEWAY_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: true,
        image_generation_provider: false,
    },
    GatewayProviderDescriptor {
        id: "vercel-ai-gateway",
        display_name: "Vercel AI Gateway",
        auth_env_vars: &["AI_GATEWAY_API_KEY"],
        auth_choice_id: "ai-gateway-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://ai-gateway.vercel.sh/v1",
            host: "ai-gateway.vercel.sh",
            api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: VERCEL_AI_GATEWAY_ALIASES,
        passthrough_provider_models: true,
        image_generation_provider: false,
    },
    GatewayProviderDescriptor {
        id: "litellm",
        display_name: "LiteLLM",
        auth_env_vars: &["LITELLM_API_KEY"],
        auth_choice_id: "litellm-api-key",
        endpoint: GatewayEndpoint::OperatorConfiguredOpenAiCompatible,
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: true,
        image_generation_provider: true,
    },
    GatewayProviderDescriptor {
        id: "deepseek",
        display_name: "DeepSeek",
        auth_env_vars: &["DEEPSEEK_API_KEY"],
        auth_choice_id: "deepseek-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://api.deepseek.com",
            host: "api.deepseek.com",
            api_path_mode: ProviderApiPathMode::AppendV1,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: false,
        image_generation_provider: false,
    },
    GatewayProviderDescriptor {
        id: "groq",
        display_name: "Groq",
        auth_env_vars: &["GROQ_API_KEY"],
        auth_choice_id: "groq-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://api.groq.com/openai/v1",
            host: "api.groq.com",
            api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: false,
        image_generation_provider: false,
    },
    GatewayProviderDescriptor {
        id: "xai",
        display_name: "xAI",
        auth_env_vars: &["XAI_API_KEY"],
        auth_choice_id: "xai-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://api.x.ai/v1",
            host: "api.x.ai",
            api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: XAI_ALIASES,
        passthrough_provider_models: false,
        image_generation_provider: true,
    },
    GatewayProviderDescriptor {
        id: "openrouter",
        display_name: "OpenRouter",
        auth_env_vars: &["OPENROUTER_API_KEY"],
        auth_choice_id: "openrouter-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://openrouter.ai/api/v1",
            host: "openrouter.ai",
            api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: true,
        image_generation_provider: true,
    },
    GatewayProviderDescriptor {
        id: "moonshot",
        display_name: "Moonshot AI",
        auth_env_vars: &["MOONSHOT_API_KEY", "KIMI_API_KEY"],
        auth_choice_id: "moonshot-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://api.moonshot.ai/v1",
            host: "api.moonshot.ai",
            api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: false,
        image_generation_provider: false,
    },
    GatewayProviderDescriptor {
        id: "kimi",
        display_name: "Kimi",
        auth_env_vars: &["KIMI_API_KEY", "KIMICODE_API_KEY"],
        auth_choice_id: "kimi-code-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://api.moonshot.ai/v1",
            host: "api.moonshot.ai",
            api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: false,
        image_generation_provider: false,
    },
    GatewayProviderDescriptor {
        id: "kimi-coding",
        display_name: "Kimi Coding",
        auth_env_vars: &["KIMI_API_KEY", "KIMICODE_API_KEY"],
        auth_choice_id: "kimi-code-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://api.moonshot.ai/v1",
            host: "api.moonshot.ai",
            api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: false,
        image_generation_provider: false,
    },
    GatewayProviderDescriptor {
        id: "qwen",
        display_name: "Qwen",
        auth_env_vars: &["QWEN_API_KEY", "MODELSTUDIO_API_KEY", "DASHSCOPE_API_KEY"],
        auth_choice_id: "qwen-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            host: "dashscope-intl.aliyuncs.com",
            api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: false,
        image_generation_provider: false,
    },
    GatewayProviderDescriptor {
        id: "together",
        display_name: "Together AI",
        auth_env_vars: &["TOGETHER_API_KEY"],
        auth_choice_id: "together-api-key",
        endpoint: GatewayEndpoint::FixedOpenAiCompatible {
            base_url: "https://api.together.xyz/v1",
            host: "api.together.xyz",
            api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
        },
        auth_headers: STANDARD_BEARER_AUTH_HEADERS,
        aliases: &[],
        passthrough_provider_models: false,
        image_generation_provider: false,
    },
];

const BASE_LLM_ROUTER_ALLOWED_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
];

pub const fn built_in_gateway_provider_descriptors() -> &'static [GatewayProviderDescriptor] {
    BUILT_IN_GATEWAY_PROVIDER_DESCRIPTORS
}

pub fn gateway_provider_descriptor(
    provider_id: &str,
) -> Option<&'static GatewayProviderDescriptor> {
    BUILT_IN_GATEWAY_PROVIDER_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.id == provider_id)
}

pub fn llm_router_host_is_allowed(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    BASE_LLM_ROUTER_ALLOWED_HOSTS.contains(&normalized.as_str())
        || BUILT_IN_GATEWAY_PROVIDER_DESCRIPTORS
            .iter()
            .filter_map(|descriptor| descriptor.endpoint.static_host())
            .any(|allowed| allowed == normalized)
}

pub fn validate_gateway_provider_catalog(
    descriptors: &[GatewayProviderDescriptor],
) -> Result<(), GatewayDescriptorError> {
    for (idx, descriptor) in descriptors.iter().enumerate() {
        if descriptor.id.trim().is_empty() {
            return Err(GatewayDescriptorError::EmptyProviderId);
        }
        if descriptors
            .iter()
            .take(idx)
            .any(|seen| seen.id == descriptor.id)
        {
            return Err(GatewayDescriptorError::DuplicateProviderId(
                descriptor.id.into(),
            ));
        }
        if descriptor.auth_env_vars.is_empty() {
            return Err(GatewayDescriptorError::MissingAuthEnvVars {
                provider_id: descriptor.id.into(),
            });
        }
        if descriptor
            .auth_env_vars
            .iter()
            .any(|env| env.trim().is_empty())
        {
            return Err(GatewayDescriptorError::EmptyAuthEnvVar {
                provider_id: descriptor.id.into(),
            });
        }
        validate_fixed_endpoint(descriptor)?;
        validate_aliases(descriptor)?;
    }
    Ok(())
}

fn validate_fixed_endpoint(
    descriptor: &GatewayProviderDescriptor,
) -> Result<(), GatewayDescriptorError> {
    let Some(base_url) = descriptor.endpoint.fixed_base_url() else {
        return Ok(());
    };
    let parsed =
        Url::parse(base_url).map_err(|error| GatewayDescriptorError::InvalidFixedBaseUrl {
            provider_id: descriptor.id.into(),
            reason: error.to_string(),
        })?;
    let host = parsed
        .host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .ok_or_else(|| GatewayDescriptorError::InvalidFixedBaseUrl {
            provider_id: descriptor.id.into(),
            reason: "missing host".into(),
        })?;
    let expected_host = descriptor.endpoint.static_host().unwrap_or_default();
    if parsed.scheme() != "https"
        || parsed.port_or_known_default() != Some(443)
        || host != expected_host
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(GatewayDescriptorError::InvalidFixedBaseUrl {
            provider_id: descriptor.id.into(),
            reason:
                "must be an https URL on the descriptor host with no userinfo, query, or fragment"
                    .into(),
        });
    }
    Ok(())
}

fn validate_aliases(descriptor: &GatewayProviderDescriptor) -> Result<(), GatewayDescriptorError> {
    for (idx, alias) in descriptor.aliases.iter().enumerate() {
        if alias.alias.trim().is_empty() || alias.canonical.trim().is_empty() {
            return Err(GatewayDescriptorError::EmptyAlias {
                provider_id: descriptor.id.into(),
            });
        }
        if descriptor
            .aliases
            .iter()
            .take(idx)
            .any(|seen| seen.alias == alias.alias)
        {
            return Err(GatewayDescriptorError::DuplicateAlias {
                provider_id: descriptor.id.into(),
                alias: alias.alias.into(),
            });
        }
    }
    Ok(())
}

fn validate_gateway_path_segment(
    field: &'static str,
    value: &str,
) -> Result<(), GatewayDescriptorError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(GatewayDescriptorError::InvalidPathSegment { field });
    }
    Ok(())
}

/// Configuration for a single provider backend.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub base_url: String,
    pub auth: ProviderAuth,
    pub api_path_mode: ProviderApiPathMode,
    pub connector_id: Option<String>,
    pub endpoint_class: String,
    pub tenant_id: Option<String>,
    pub region: Option<String>,
    pub resource: Option<String>,
    pub allow_openrouter_fallback: bool,
    pub extra_headers: Vec<ProviderHttpHeader>,
    pub models: Vec<ModelInfo>,
    pub priority: u32,
    pub passthrough_provider_models: bool,
    pub image_generation_provider: bool,
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
    #[serde(default)]
    pub deployment_aliases: Vec<String>,
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

    const TEST_AUTH_ENV_VARS: &[&str] = &["TEST_API_KEY"];
    const TEST_AUTH_HEADERS: &[GatewayAuthHeader] = &[GatewayAuthHeader::AuthorizationBearer];
    const TEST_ALIASES: &[GatewayModelAlias] = &[];

    fn test_gateway_descriptor(id: &'static str) -> GatewayProviderDescriptor {
        GatewayProviderDescriptor {
            id,
            display_name: "Test Gateway",
            auth_env_vars: TEST_AUTH_ENV_VARS,
            auth_choice_id: "test-api-key",
            endpoint: GatewayEndpoint::FixedOpenAiCompatible {
                base_url: "https://gateway.test.example/v1",
                host: "gateway.test.example",
                api_path_mode: ProviderApiPathMode::OpenAiCompatibleBase,
            },
            auth_headers: TEST_AUTH_HEADERS,
            aliases: TEST_ALIASES,
            passthrough_provider_models: true,
            image_generation_provider: false,
        }
    }

    #[test]
    fn built_in_gateway_provider_catalog_is_valid() {
        validate_gateway_provider_catalog(built_in_gateway_provider_descriptors()).unwrap();
    }

    #[test]
    fn gateway_host_policy_admits_existing_and_static_gateway_hosts() {
        assert!(llm_router_host_is_allowed("api.anthropic.com"));
        assert!(llm_router_host_is_allowed("api.openai.com."));
        assert!(llm_router_host_is_allowed(
            "GENerativelanguage.googleapis.com"
        ));
        assert!(llm_router_host_is_allowed("gateway.ai.cloudflare.com"));
        assert!(llm_router_host_is_allowed("ai-gateway.vercel.sh"));
        assert!(llm_router_host_is_allowed("api.deepseek.com"));
        assert!(llm_router_host_is_allowed("api.groq.com"));
        assert!(llm_router_host_is_allowed("api.x.ai"));
        assert!(llm_router_host_is_allowed("openrouter.ai"));
        assert!(llm_router_host_is_allowed("api.moonshot.ai"));
        assert!(llm_router_host_is_allowed("dashscope-intl.aliyuncs.com"));
        assert!(llm_router_host_is_allowed("api.together.xyz"));
        assert!(!llm_router_host_is_allowed("api.cloudflare.com"));
        assert!(!llm_router_host_is_allowed("api.vercel.com"));
        assert!(!llm_router_host_is_allowed("localhost"));
    }

    #[test]
    fn cloudflare_gateway_base_url_is_built_from_segments() {
        let descriptor = gateway_provider_descriptor("cloudflare-ai-gateway").unwrap();
        let base_url = descriptor
            .endpoint
            .cloudflare_base_url(" account_123 ", "gateway-prod")
            .unwrap();
        assert_eq!(
            base_url,
            "https://gateway.ai.cloudflare.com/v1/account_123/gateway-prod/openai"
        );

        let err = descriptor
            .endpoint
            .cloudflare_base_url("account/123", "gateway-prod")
            .unwrap_err();
        assert!(matches!(
            err,
            GatewayDescriptorError::InvalidPathSegment {
                field: "account_id"
            }
        ));
    }

    #[test]
    fn cloudflare_gateway_base_url_rejects_path_query_and_fragment_input() {
        let descriptor = gateway_provider_descriptor("cloudflare-ai-gateway").unwrap();
        for (account_id, gateway_id, field) in [
            ("account/123", "gateway-prod", "account_id"),
            ("account?123", "gateway-prod", "account_id"),
            ("account_123", "gateway#prod", "gateway_id"),
            ("account_123", "gateway.prod", "gateway_id"),
        ] {
            let err = descriptor
                .endpoint
                .cloudflare_base_url(account_id, gateway_id)
                .unwrap_err();
            assert!(
                matches!(err, GatewayDescriptorError::InvalidPathSegment { field: actual } if actual == field),
                "expected invalid {field}, got {err:?}"
            );
        }
    }

    #[test]
    fn cloudflare_gateway_auth_header_validates_and_redacts_secret() {
        let header =
            ProviderHttpHeader::cloudflare_ai_gateway_authorization("cf-gateway-secret").unwrap();
        assert_eq!(
            header.name().as_str(),
            CLOUDFLARE_AI_GATEWAY_AUTH_HEADER_NAME
        );
        assert_eq!(header.value().to_str().unwrap(), "Bearer cf-gateway-secret");

        let debug = format!("{header:?}");
        assert!(debug.contains(CLOUDFLARE_AI_GATEWAY_AUTH_HEADER_NAME));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("cf-gateway-secret"));
        assert_eq!(header.redacted_label(), "cf-aig-authorization:[redacted]");
    }

    #[test]
    fn cloudflare_gateway_auth_header_rejects_header_injection() {
        let err =
            ProviderHttpHeader::cloudflare_ai_gateway_authorization("cf-good\r\nx-injected: bad")
                .unwrap_err();
        let message = err.to_string();
        assert!(!message.contains("cf-good"));
        assert!(!message.contains("x-injected"));
    }

    #[test]
    fn cloudflare_base_url_rejects_wrong_endpoint_kind() {
        let descriptor = gateway_provider_descriptor("vercel-ai-gateway").unwrap();
        let err = descriptor
            .endpoint
            .cloudflare_base_url("account", "gateway")
            .unwrap_err();
        assert_eq!(err, GatewayDescriptorError::WrongEndpointKind);
    }

    #[test]
    fn vercel_gateway_aliases_normalize_bare_claude_names() {
        let descriptor = gateway_provider_descriptor("vercel-ai-gateway").unwrap();
        assert_eq!(
            descriptor.normalize_model_id("opus-4.6"),
            "anthropic/claude-opus-4-6"
        );
        assert_eq!(
            descriptor.normalize_model_id("sonnet-4.5"),
            "anthropic/claude-sonnet-4-5"
        );
        assert_eq!(
            descriptor.normalize_model_id("anthropic/claude-opus-4.6"),
            "anthropic/claude-opus-4.6"
        );
    }

    #[test]
    fn vercel_gateway_descriptor_has_fixed_base_url_and_auth_metadata() {
        let descriptor = gateway_provider_descriptor("vercel-ai-gateway").unwrap();
        assert_eq!(
            descriptor.endpoint.fixed_base_url(),
            Some("https://ai-gateway.vercel.sh/v1")
        );
        assert_eq!(
            descriptor.endpoint.api_path_mode(),
            ProviderApiPathMode::OpenAiCompatibleBase
        );
        assert_eq!(
            descriptor.endpoint.static_host(),
            Some("ai-gateway.vercel.sh")
        );
        assert_eq!(descriptor.auth_env_vars, &["AI_GATEWAY_API_KEY"]);
        assert_eq!(descriptor.auth_choice_id, "ai-gateway-api-key");
        assert_eq!(descriptor.auth_headers, STANDARD_BEARER_AUTH_HEADERS);
        assert!(descriptor.passthrough_provider_models);
        assert!(!descriptor.image_generation_provider);
    }

    #[test]
    fn fixed_long_tail_descriptors_preserve_openai_compatible_path_modes() {
        for (id, base_url, path_mode, env_vars) in [
            (
                "deepseek",
                "https://api.deepseek.com",
                ProviderApiPathMode::AppendV1,
                &["DEEPSEEK_API_KEY"][..],
            ),
            (
                "groq",
                "https://api.groq.com/openai/v1",
                ProviderApiPathMode::OpenAiCompatibleBase,
                &["GROQ_API_KEY"][..],
            ),
            (
                "xai",
                "https://api.x.ai/v1",
                ProviderApiPathMode::OpenAiCompatibleBase,
                &["XAI_API_KEY"][..],
            ),
            (
                "openrouter",
                "https://openrouter.ai/api/v1",
                ProviderApiPathMode::OpenAiCompatibleBase,
                &["OPENROUTER_API_KEY"][..],
            ),
            (
                "moonshot",
                "https://api.moonshot.ai/v1",
                ProviderApiPathMode::OpenAiCompatibleBase,
                &["MOONSHOT_API_KEY", "KIMI_API_KEY"][..],
            ),
            (
                "kimi-coding",
                "https://api.moonshot.ai/v1",
                ProviderApiPathMode::OpenAiCompatibleBase,
                &["KIMI_API_KEY", "KIMICODE_API_KEY"][..],
            ),
            (
                "qwen",
                "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
                ProviderApiPathMode::OpenAiCompatibleBase,
                &["QWEN_API_KEY", "MODELSTUDIO_API_KEY", "DASHSCOPE_API_KEY"][..],
            ),
            (
                "together",
                "https://api.together.xyz/v1",
                ProviderApiPathMode::OpenAiCompatibleBase,
                &["TOGETHER_API_KEY"][..],
            ),
        ] {
            let descriptor = gateway_provider_descriptor(id).unwrap();
            assert_eq!(descriptor.endpoint.fixed_base_url(), Some(base_url));
            assert_eq!(descriptor.endpoint.api_path_mode(), path_mode);
            assert_eq!(descriptor.auth_env_vars, env_vars);
            assert_eq!(descriptor.auth_headers, STANDARD_BEARER_AUTH_HEADERS);
        }
    }

    #[test]
    fn xai_aliases_normalize_openclaw_reasoning_names() {
        let descriptor = gateway_provider_descriptor("xai").unwrap();
        assert_eq!(
            descriptor.normalize_model_id("grok-4-fast-reasoning"),
            "grok-4-fast"
        );
        assert_eq!(
            descriptor.normalize_model_id("grok-4.20-non-reasoning"),
            "grok-4.20-beta-latest-non-reasoning"
        );
    }

    #[test]
    fn litellm_descriptor_is_operator_configured_and_image_capable() {
        let descriptor = gateway_provider_descriptor("litellm").unwrap();
        assert_eq!(descriptor.endpoint.static_host(), None);
        assert_eq!(descriptor.endpoint.fixed_base_url(), None);
        assert!(descriptor.passthrough_provider_models);
        assert!(descriptor.image_generation_provider);
        assert_eq!(descriptor.auth_env_vars, &["LITELLM_API_KEY"]);
        assert_eq!(descriptor.auth_choice_id, "litellm-api-key");
        assert_eq!(descriptor.auth_headers, STANDARD_BEARER_AUTH_HEADERS);
        assert!(descriptor.aliases.is_empty());
    }

    #[test]
    fn microsoft_foundry_descriptor_is_dynamic_first_party_provider() {
        let descriptor = gateway_provider_descriptor("microsoft-foundry").unwrap();
        assert_eq!(descriptor.display_name, "Microsoft Foundry");
        assert_eq!(descriptor.endpoint.static_host(), None);
        assert_eq!(descriptor.endpoint.fixed_base_url(), None);
        assert_eq!(
            descriptor.endpoint.api_path_mode(),
            ProviderApiPathMode::OpenAiCompatibleBase
        );
        assert_eq!(
            descriptor.auth_env_vars,
            &["MICROSOFT_FOUNDRY_API_KEY", "AZURE_OPENAI_API_KEY"]
        );
        assert_eq!(descriptor.auth_choice_id, "microsoft-foundry-credential");
        assert!(!descriptor.passthrough_provider_models);
        assert!(!descriptor.image_generation_provider);
    }

    #[test]
    fn gateway_catalog_validation_rejects_duplicate_provider_ids() {
        let descriptors = [
            test_gateway_descriptor("duplicate"),
            test_gateway_descriptor("duplicate"),
        ];
        let err = validate_gateway_provider_catalog(&descriptors).unwrap_err();
        assert_eq!(
            err,
            GatewayDescriptorError::DuplicateProviderId("duplicate".into())
        );
    }

    #[test]
    fn gateway_catalog_validation_rejects_missing_auth_env_vars() {
        let descriptor = GatewayProviderDescriptor {
            auth_env_vars: &[],
            ..test_gateway_descriptor("missing-auth")
        };
        let err = validate_gateway_provider_catalog(&[descriptor]).unwrap_err();
        assert_eq!(
            err,
            GatewayDescriptorError::MissingAuthEnvVars {
                provider_id: "missing-auth".into()
            }
        );
    }

    #[test]
    fn gateway_catalog_validation_rejects_duplicate_aliases() {
        const DUP_ALIASES: &[GatewayModelAlias] = &[
            GatewayModelAlias {
                alias: "mini",
                canonical: "model-a",
            },
            GatewayModelAlias {
                alias: "mini",
                canonical: "model-b",
            },
        ];
        let descriptor = GatewayProviderDescriptor {
            aliases: DUP_ALIASES,
            ..test_gateway_descriptor("aliases")
        };
        let err = validate_gateway_provider_catalog(&[descriptor]).unwrap_err();
        assert_eq!(
            err,
            GatewayDescriptorError::DuplicateAlias {
                provider_id: "aliases".into(),
                alias: "mini".into()
            }
        );
    }

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
        assert_eq!(label, "api_key:[redacted]");
        assert!(!label.contains("sk-1234"));
        assert!(!label.contains("cdef"));
    }

    #[test]
    fn provider_auth_redacted_label_short_key() {
        let auth = ProviderAuth::ApiKey("short".into());
        let label = auth.redacted_label();
        assert_eq!(label, "api_key:[redacted]");
    }

    #[test]
    fn provider_auth_redacted_label_credential_id() {
        let auth = ProviderAuth::CredentialId("my-uuid-123".into());
        assert_eq!(auth.redacted_label(), "credential_id:my-uuid-123");
    }

    #[test]
    fn provider_auth_api_key_builds_bearer_header() {
        let auth = ProviderAuth::ApiKey("sk-header-safe".into());
        let header = auth.bearer_authorization_header().unwrap().unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer sk-header-safe");
    }

    #[test]
    fn provider_auth_rejects_header_unsafe_api_key() {
        let auth = ProviderAuth::ApiKey("sk-good\r\nsk-bad".into());
        assert!(auth.bearer_authorization_header().is_err());
    }

    #[test]
    fn provider_auth_credential_id_has_no_direct_header() {
        let auth = ProviderAuth::CredentialId("cred-123".into());
        assert!(auth.bearer_authorization_header().unwrap().is_none());
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
            deployment_aliases: Vec::new(),
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
        let cloned = original; // Copy
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
        let cloned = original; // Copy
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
        assert_eq!(format!("{:?}", ProviderStatus::Unavailable), "Unavailable");
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
        let cloned = original; // Copy
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
        assert_eq!(format!("{:?}", ModelCapability::LongContext), "LongContext");
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
        let lc: ModelCapability = serde_json::from_str("\"long_context\"").unwrap();
        assert_eq!(lc, ModelCapability::LongContext);
        let v: ModelCapability = serde_json::from_str("\"vision\"").unwrap();
        assert_eq!(v, ModelCapability::Vision);
    }

    // ---- BudgetEnforcement: Clone, Copy, serialize lowercase, Debug ----

    #[test]
    fn budget_enforcement_clone() {
        let original = BudgetEnforcement::Hard;
        let cloned = original; // Copy
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
    fn provider_auth_debug_hides_key() {
        let auth = ProviderAuth::ApiKey("sk-mysecretkey".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiKey"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("sk-my"));
        assert!(!dbg.contains("secretkey"));
    }

    #[test]
    fn provider_auth_redacted_label_exact_8_char_key() {
        let auth = ProviderAuth::ApiKey("12345678".into());
        assert_eq!(auth.redacted_label(), "api_key:[redacted]");
    }

    #[test]
    fn provider_auth_redacted_label_9_char_key() {
        let auth = ProviderAuth::ApiKey("123456789".into());
        assert_eq!(auth.redacted_label(), "api_key:[redacted]");
    }

    #[test]
    fn provider_auth_redacted_label_empty_key() {
        let auth = ProviderAuth::ApiKey(String::new());
        assert_eq!(auth.redacted_label(), "api_key:[redacted]");
    }

    #[test]
    fn provider_auth_redacted_label_empty_credential_id() {
        let auth = ProviderAuth::CredentialId(String::new());
        assert_eq!(auth.redacted_label(), "credential_id:");
    }

    // ---- ProviderConfig: Clone, Debug, empty models ----

    #[test]
    #[allow(clippy::redundant_clone)]
    fn provider_config_clone() {
        let config = ProviderConfig {
            name: "openai".into(),
            base_url: "https://api.openai.com".into(),
            auth: ProviderAuth::ApiKey("sk-test-123456789".into()),
            api_path_mode: ProviderApiPathMode::AppendV1,
            connector_id: None,
            endpoint_class: "legacy_openai_compatible".into(),
            tenant_id: None,
            region: None,
            resource: None,
            allow_openrouter_fallback: false,
            extra_headers: Vec::new(),
            models: vec![],
            priority: 1,
            passthrough_provider_models: false,
            image_generation_provider: false,
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
            api_path_mode: ProviderApiPathMode::AppendV1,
            connector_id: None,
            endpoint_class: "legacy_openai_compatible".into(),
            tenant_id: None,
            region: None,
            resource: None,
            allow_openrouter_fallback: false,
            extra_headers: Vec::new(),
            models: vec![],
            priority: 2,
            passthrough_provider_models: false,
            image_generation_provider: false,
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
            api_path_mode: ProviderApiPathMode::AppendV1,
            connector_id: None,
            endpoint_class: "legacy_openai_compatible".into(),
            tenant_id: None,
            region: None,
            resource: None,
            allow_openrouter_fallback: false,
            extra_headers: Vec::new(),
            models: vec![],
            priority: 0,
            passthrough_provider_models: false,
            image_generation_provider: false,
        };
        assert!(config.models.is_empty());
        assert_eq!(config.priority, 0);
    }

    // ---- ProviderReadiness: Clone, Debug, all-false ----

    #[test]
    #[allow(clippy::redundant_clone)]
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
    #[allow(clippy::redundant_clone)]
    fn model_info_clone() {
        let model = ModelInfo {
            id: "claude-3".into(),
            deployment_aliases: Vec::new(),
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
            deployment_aliases: Vec::new(),
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
            deployment_aliases: Vec::new(),
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
            deployment_aliases: Vec::new(),
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
    #[allow(clippy::redundant_clone)]
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
    #[allow(clippy::redundant_clone)]
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
    #[allow(clippy::redundant_clone)]
    fn provider_usage_clone() {
        let usage = ProviderUsage {
            requests: 10,
            cost_usd: 0.5,
            ..Default::default()
        };
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

    // ── Additional RoutingStrategy tests ──────────────────────────

    #[test]
    fn routing_strategy_from_str_opt_case_sensitive() {
        assert_eq!(RoutingStrategy::from_str_opt("COST"), None);
        assert_eq!(RoutingStrategy::from_str_opt("Fallback"), None);
        assert_eq!(RoutingStrategy::from_str_opt("LATENCY"), None);
        assert_eq!(RoutingStrategy::from_str_opt("Capability"), None);
    }

    #[test]
    fn routing_strategy_deserialize_from_json_value() {
        let v = serde_json::json!("cost");
        let s: RoutingStrategy = serde_json::from_value(v).unwrap();
        assert_eq!(s, RoutingStrategy::Cost);
    }

    #[test]
    fn routing_strategy_deserialize_invalid_fails() {
        let v = serde_json::json!("round_robin");
        assert!(serde_json::from_value::<RoutingStrategy>(v).is_err());
    }

    // ── Additional ModelCapability tests ──────────────────────────

    #[test]
    fn model_capability_from_str_opt_case_sensitive() {
        assert_eq!(ModelCapability::from_str_opt("VISION"), None);
        assert_eq!(ModelCapability::from_str_opt("Tool_Use"), None);
        assert_eq!(ModelCapability::from_str_opt("longContext"), None);
    }

    #[test]
    fn model_capability_deserialize_invalid_fails() {
        let v = serde_json::json!("flying");
        assert!(serde_json::from_value::<ModelCapability>(v).is_err());
    }

    // ── Additional BudgetEnforcement tests ────────────────────────

    #[test]
    fn budget_enforcement_deserialize_invalid_fails() {
        let v = serde_json::json!("strict");
        assert!(serde_json::from_value::<BudgetEnforcement>(v).is_err());
    }

    #[test]
    fn budget_enforcement_eq_and_ne() {
        assert_eq!(BudgetEnforcement::Hard, BudgetEnforcement::Hard);
        assert_ne!(BudgetEnforcement::Hard, BudgetEnforcement::Soft);
        assert_ne!(BudgetEnforcement::Soft, BudgetEnforcement::None);
    }

    // ── ProviderStatus additional ─────────────────────────────────

    #[test]
    fn provider_status_deserialize_invalid_fails() {
        let v = serde_json::json!("offline");
        assert!(serde_json::from_value::<ProviderStatus>(v).is_err());
    }

    #[test]
    fn provider_status_eq_all_combos() {
        let variants = [
            ProviderStatus::Healthy,
            ProviderStatus::Degraded,
            ProviderStatus::Unavailable,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── ProviderAuth edge cases ───────────────────────────────────

    #[test]
    fn provider_auth_api_key_1_char() {
        let auth = ProviderAuth::ApiKey("x".into());
        assert_eq!(auth.redacted_label(), "api_key:[redacted]");
    }

    #[test]
    fn provider_auth_api_key_unicode() {
        let auth = ProviderAuth::ApiKey("sk-日本語テストキーです".into());
        let label = auth.redacted_label();
        assert_eq!(label, "api_key:[redacted]");
    }

    #[test]
    fn provider_auth_credential_id_debug() {
        let auth = ProviderAuth::CredentialId("my-cred-id".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains("my-cred-id"));
    }

    // ── ModelInfo additional ───────────────────────────────────────

    #[test]
    fn model_info_all_capabilities() {
        let model = ModelInfo {
            id: "all-caps".into(),
            deployment_aliases: Vec::new(),
            capabilities: vec![
                ModelCapability::Responses,
                ModelCapability::Chat,
                ModelCapability::Vision,
                ModelCapability::ToolUse,
                ModelCapability::LongContext,
                ModelCapability::Code,
                ModelCapability::Math,
                ModelCapability::Streaming,
                ModelCapability::Embeddings,
            ],
            context_window: 1_000_000,
            cost_per_input_token: 0.001,
            cost_per_output_token: 0.002,
        };
        assert_eq!(model.capabilities.len(), 9);
        let json = serde_json::to_value(&model).unwrap();
        let caps = json["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 9);
    }

    #[test]
    fn model_info_large_context_window() {
        let model = ModelInfo {
            id: "huge".into(),
            deployment_aliases: Vec::new(),
            capabilities: vec![],
            context_window: u32::MAX,
            cost_per_input_token: 0.0,
            cost_per_output_token: 0.0,
        };
        assert_eq!(model.context_window, u32::MAX);
    }

    // ── RoutingDecision edge cases ────────────────────────────────

    #[test]
    fn routing_decision_zero_candidates() {
        let decision = RoutingDecision {
            strategy_used: "cost".into(),
            candidates_evaluated: 0,
            fallback_used: false,
            reason: "no candidates".into(),
        };
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["candidates_evaluated"], 0);
    }

    #[test]
    fn routing_decision_empty_reason() {
        let decision = RoutingDecision {
            strategy_used: "latency".into(),
            candidates_evaluated: 1,
            fallback_used: false,
            reason: String::new(),
        };
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["reason"], "");
    }

    // ── BudgetConfig edge cases ───────────────────────────────────

    #[test]
    fn budget_config_zero_budget() {
        let config = BudgetConfig {
            budget_usd: 0.0,
            enforcement: BudgetEnforcement::Hard,
            period: "daily".into(),
        };
        assert_eq!(config.budget_usd, 0.0);
    }

    #[test]
    fn budget_config_negative_budget() {
        let config = BudgetConfig {
            budget_usd: -1.0,
            enforcement: BudgetEnforcement::Soft,
            period: "monthly".into(),
        };
        assert!(config.budget_usd < 0.0);
    }

    // ── ProviderUsage edge cases ──────────────────────────────────

    #[test]
    fn provider_usage_large_values() {
        let usage = ProviderUsage {
            input_tokens: u64::MAX,
            output_tokens: u64::MAX,
            cost_usd: f64::MAX,
            requests: u64::MAX,
            errors: u64::MAX,
            total_latency_ms: u64::MAX,
        };
        assert_eq!(usage.input_tokens, u64::MAX);
        assert_eq!(usage.cost_usd, f64::MAX);
    }

    // ── ProviderReadiness serialize completeness ──────────────────

    #[test]
    fn provider_readiness_all_true_serializes_correctly() {
        let readiness = ProviderReadiness {
            name: "test".into(),
            auth_ok: true,
            auth_mode: "api_key".into(),
            network_ok: true,
            models_ok: true,
            model_count: 10,
        };
        let json = serde_json::to_value(&readiness).unwrap();
        assert_eq!(json["auth_ok"], true);
        assert_eq!(json["network_ok"], true);
        assert_eq!(json["models_ok"], true);
        assert_eq!(json["model_count"], 10);
    }
}
