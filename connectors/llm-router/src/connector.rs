//! FCP LLM Router Connector implementation.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass,
    Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
};
use serde_json::json;
use tracing::{info, instrument};
use url::{Host, Url};

use crate::error::RouterError;
use crate::routing;
use crate::types::{
    BudgetConfig, BudgetEnforcement, GatewayEndpoint, ModelCapability, ModelInfo,
    ProviderApiPathMode, ProviderAuth, ProviderConfig, ProviderHttpHeader, ProviderReadiness,
    ProviderStatus, ProviderUsage, RoutingDecision, RoutingStrategy,
    built_in_gateway_provider_descriptors, gateway_provider_descriptor, llm_router_host_is_allowed,
};

/// Router configuration parsed from `configure` params.
#[derive(Debug, Clone)]
struct RouterConfig {
    providers: Vec<ProviderConfig>,
    default_strategy: RoutingStrategy,
    budget: BudgetConfig,
}

/// FCP LLM Router Connector.
pub struct LlmRouterConnector {
    base: Arc<BaseConnector>,
    config: Option<RouterConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    total_cost: AtomicU64,
    provider_usage: HashMap<String, ProviderUsage>,
    provider_status: Vec<(String, ProviderStatus, u64)>,
}

impl LlmRouterConnector {
    /// Create a new LLM Router connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("llm-router"))),
            config: None,
            verifier: None,
            session_id: None,
            total_cost: AtomicU64::new(0),
            provider_usage: HashMap::new(),
            provider_status: Vec::new(),
        }
    }

    fn total_cost(&self) -> f64 {
        self.total_cost.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
    }

    fn track_cost(&self, cost: f64) {
        let cost_fixed = (cost * 1_000_000_000.0) as u64;
        self.total_cost.fetch_add(cost_fixed, Ordering::Relaxed);
    }

    fn config_ref(&self) -> FcpResult<&RouterConfig> {
        self.config.as_ref().ok_or(FcpError::InvalidRequest {
            code: 1001,
            message: "Connector not configured".into(),
        })
    }

    fn verify_capability(
        &self,
        params: &serde_json::Value,
        required_cap: &str,
        operation: &str,
    ) -> FcpResult<()> {
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::Unauthorized {
                code: 2001,
                message: "Missing capability_token".into(),
            })?;

        // Try proper COSE token verification when the token is a real
        // CapabilityToken (byte-array or base64 in JSON).
        if let Ok(token) = serde_json::from_value::<CapabilityToken>(token_value.clone()) {
            if let Some(verifier) = &self.verifier {
                let cap_id: CapabilityId =
                    required_cap.parse().map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "Invalid capability ID format".into(),
                    })?;
                let op_id: OperationId =
                    operation.parse().map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "Invalid operation ID format".into(),
                    })?;
                verifier.verify_bound(token, &cap_id, &op_id, &[])?;
            }
            return Ok(());
        }

        // Fallback for legacy string tokens: presence check only.
        if !token_value.is_string() {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: "Invalid capability_token format".into(),
            });
        }

        Ok(())
    }

    fn operation_input_schema(op: &str) -> Option<serde_json::Value> {
        match op {
            "llm-router.route" => Some(json!({
                "type": "object",
                "required": ["messages"],
                "properties": {
                    "messages": {
                        "type": "array",
                        "minItems": 1,
                        "description": "Conversation messages [{role, content}]"
                    },
                    "strategy": {
                        "type": "string",
                        "enum": ["cost", "latency", "capability", "fallback"],
                        "default": "cost"
                    },
                    "preferred_provider": { "type": "string" },
                    "preferred_model": { "type": "string" },
                    "max_tokens": { "type": "integer", "default": 4096 },
                    "temperature": { "type": "number" },
                    "tools": { "type": "array" },
                    "budget_limit_usd": { "type": "number" },
                    "required_capabilities": { "type": "array" }
                }
            })),
            "llm-router.estimate_cost" => Some(json!({
                "type": "object",
                "required": ["messages"],
                "properties": {
                    "messages": { "type": "array", "minItems": 1 },
                    "max_tokens": { "type": "integer", "default": 4096 },
                    "providers": { "type": "array" }
                }
            })),
            "llm-router.list_providers" => Some(json!({
                "type": "object",
                "properties": {
                    "include_models": { "type": "boolean", "default": false }
                }
            })),
            "llm-router.get_usage" => Some(json!({
                "type": "object",
                "properties": {
                    "group_by": {
                        "type": "string",
                        "enum": ["provider", "model", "none"],
                        "default": "none"
                    }
                }
            })),
            "llm-router.get_budget" => Some(json!({
                "type": "object"
            })),
            _ => None,
        }
    }

    fn operation_output_schema(op: &str) -> Option<serde_json::Value> {
        match op {
            "llm-router.route" => Some(json!({
                "type": "object",
                "required": [
                    "dispatch_required",
                    "dispatch_instruction",
                    "provider",
                    "model",
                    "usage",
                    "cost_usd",
                    "routing_decision",
                    "provenance"
                ],
                "properties": {
                    "dispatch_required": { "type": "boolean" },
                    "dispatch_instruction": { "type": "string" },
                    "provider": { "type": "string" },
                    "model": { "type": "string" },
                    "usage": { "type": "object" },
                    "cost_usd": { "type": "number" },
                    "routing_decision": { "type": "object" },
                    "provenance": { "type": "object" }
                }
            })),
            "llm-router.estimate_cost" => Some(json!({
                "type": "object",
                "required": ["estimates"],
                "properties": {
                    "estimates": { "type": "array" },
                    "recommended": { "type": "object" }
                }
            })),
            "llm-router.list_providers" => Some(json!({
                "type": "object",
                "required": ["providers"],
                "properties": {
                    "providers": { "type": "array" }
                }
            })),
            "llm-router.get_usage" => Some(json!({
                "type": "object",
                "required": ["total_input_tokens", "total_output_tokens", "total_cost_usd", "requests_total", "requests_error"],
                "properties": {
                    "total_input_tokens": { "type": "integer" },
                    "total_output_tokens": { "type": "integer" },
                    "total_cost_usd": { "type": "number" },
                    "requests_total": { "type": "integer" },
                    "requests_error": { "type": "integer" },
                    "breakdown": { "type": "array" }
                }
            })),
            "llm-router.get_budget" => Some(json!({
                "type": "object",
                "required": ["budget_usd", "spent_usd", "remaining_usd", "enforcement"],
                "properties": {
                    "budget_usd": { "type": "number" },
                    "spent_usd": { "type": "number" },
                    "remaining_usd": { "type": "number" },
                    "enforcement": { "type": "string" }
                }
            })),
            _ => None,
        }
    }

    // -------------------------------------------------------------------------
    // FCP Protocol Handlers
    // -------------------------------------------------------------------------

    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let providers = Self::parse_providers(&params)?;
        if providers.is_empty() {
            return Err(RouterError::NoProviders.into());
        }

        // Validate network constraints before accepting configuration
        Self::validate_network_constraints(&providers)?;

        let default_strategy = params
            .get("default_strategy")
            .and_then(|v| v.as_str())
            .and_then(RoutingStrategy::from_str_opt)
            .unwrap_or_default();

        let budget = Self::parse_budget(&params);

        // Build provisioning readiness per provider
        let readiness = Self::provider_readiness(&providers);

        // Initialize provider status as healthy
        let provider_status: Vec<_> = providers
            .iter()
            .map(|p| (p.name.clone(), ProviderStatus::Healthy, 100u64))
            .collect();

        let provider_names: Vec<_> = providers.iter().map(|p| p.name.clone()).collect();

        // Log auth modes (redacted)
        for p in &providers {
            info!(
                provider = %p.name,
                auth = %p.auth.redacted_label(),
                models = p.models.len(),
                "Provider configured"
            );
        }

        self.config = Some(RouterConfig {
            providers,
            default_strategy,
            budget,
        });
        self.provider_status = provider_status;
        self.base.set_configured(true);

        info!(
            providers = ?provider_names,
            strategy = ?default_strategy,
            "LLM Router configured"
        );

        Ok(json!({
            "status": "configured",
            "providers": provider_names,
            "default_strategy": default_strategy,
            "provisioning": readiness,
        }))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid handshake: {e}"),
            })?;

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        // Create capability verifier from host public key for token verification.
        let instance_id = req.requested_instance_id.clone().unwrap_or_default();
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            instance_id,
        ));

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "blake3-256:fcp.interface.v2:pending".into(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let status = if configured { "ok" } else { "unconfigured" };
        Ok(json!({
            "status": status,
            "configured": configured,
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // Check 1: Configuration loaded (CRITICAL)
        let configured = self.config.is_some();
        checks.push(json!({
            "name": "configuration",
            "passed": configured,
            "critical": true,
            "message": if configured { "Configuration loaded" } else { "Not configured - run configure first" },
        }));

        let Some(config) = &self.config else {
            return Ok(json!({
                "status": "unhealthy",
                "checks": checks,
            }));
        };

        // Check 2: Provider count (CRITICAL)
        let provider_count = config.providers.len();
        checks.push(json!({
            "name": "providers",
            "passed": provider_count > 0,
            "critical": true,
            "message": format!("{provider_count} provider(s) configured"),
        }));

        // Check 3: Per-provider auth + network + status
        for p in &config.providers {
            let network_ok = Self::provider_host_allowed(p);
            let (status, _) = self
                .provider_status
                .iter()
                .find(|(n, _, _)| n == &p.name)
                .map(|(_, s, l)| (*s, *l))
                .unwrap_or((ProviderStatus::Healthy, 100));

            checks.push(json!({
                "name": format!("provider.{}", p.name),
                "passed": status != ProviderStatus::Unavailable && network_ok,
                "critical": false,
                "message": format!(
                    "{}: auth={}, network={}, status={:?}, models={}",
                    p.name,
                    p.auth.redacted_label(),
                    if network_ok { "ok" } else { "VIOLATION" },
                    status,
                    p.models.len()
                ),
            }));
        }

        // Check 4: Network constraints (CRITICAL)
        let all_hosts_ok = config.providers.iter().all(Self::provider_host_allowed);
        checks.push(json!({
            "name": "network_constraints",
            "passed": all_hosts_ok,
            "critical": true,
            "message": if all_hosts_ok {
                "All provider base_urls within NetworkConstraints".to_string()
            } else {
                let violators: Vec<_> = config.providers.iter()
                    .filter(|p| !Self::provider_host_allowed(p))
                    .map(|p| format!("{}={}", p.name, p.base_url))
                    .collect();
                format!("NetworkConstraints violated: {}", violators.join(", "))
            },
        }));

        // Check 5: Credential injection status (informational)
        let any_secretless = config.providers.iter().any(|p| p.auth.is_secretless());
        checks.push(json!({
            "name": "credential_injection",
            "passed": true,
            "critical": false,
            "message": if any_secretless {
                "One or more providers use credential_id (egress proxy injection required)".to_string()
            } else {
                "All providers use direct API keys".to_string()
            },
        }));

        // Check 6: Budget configuration (informational)
        checks.push(json!({
            "name": "budget",
            "passed": true,
            "critical": false,
            "message": format!(
                "Budget: {} USD ({:?} enforcement, {} period)",
                if config.budget.budget_usd.is_infinite() { "unlimited".into() } else { format!("{:.2}", config.budget.budget_usd) },
                config.budget.enforcement,
                config.budget.period
            ),
        }));

        let all_passed = checks
            .iter()
            .all(|c| c.get("passed").and_then(|v| v.as_bool()).unwrap_or(false));
        let any_critical_failed = checks.iter().any(|c| {
            c.get("critical").and_then(|v| v.as_bool()).unwrap_or(false)
                && !c.get("passed").and_then(|v| v.as_bool()).unwrap_or(true)
        });

        let status = if any_critical_failed {
            "unhealthy"
        } else if all_passed {
            "healthy"
        } else {
            "degraded"
        };

        Ok(json!({
            "status": status,
            "checks": checks,
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        // Not configured at all
        let Some(config) = &self.config else {
            return Ok(json!({
                "ready": false,
                "status": "degraded",
                "reason_code": "not_configured",
                "reasons": [{"code": "not_configured", "message": "Connector is not configured", "severity": "error"}],
            }));
        };

        let mut reasons = Vec::new();
        let readiness = Self::provider_readiness(&config.providers);

        // Check: no providers
        if config.providers.is_empty() {
            reasons.push(json!({
                "code": "no_providers",
                "message": "No providers configured",
                "severity": "error",
            }));
        }

        // Check: credential injection needed
        let secretless_providers: Vec<_> = config
            .providers
            .iter()
            .filter(|p| p.auth.is_secretless())
            .map(|p| p.name.clone())
            .collect();

        if !secretless_providers.is_empty() {
            reasons.push(json!({
                "code": "credential_injection_required",
                "message": format!(
                    "Providers using credential_id (egress proxy required): {}",
                    secretless_providers.join(", ")
                ),
                "severity": "info",
            }));
        }

        // Check: network constraint violations
        let network_violations: Vec<_> = config
            .providers
            .iter()
            .filter(|p| !Self::provider_host_allowed(p))
            .map(|p| p.name.clone())
            .collect();

        if !network_violations.is_empty() {
            reasons.push(json!({
                "code": "network_constraints_violated",
                "message": format!(
                    "Providers violating NetworkConstraints: {}",
                    network_violations.join(", ")
                ),
                "severity": "error",
            }));
        }

        // Check: unavailable providers
        let unavailable: Vec<_> = self
            .provider_status
            .iter()
            .filter(|(_, s, _)| *s == ProviderStatus::Unavailable)
            .map(|(n, _, _)| n.clone())
            .collect();

        if !unavailable.is_empty() {
            reasons.push(json!({
                "code": "providers_unavailable",
                "message": format!("Unavailable providers: {}", unavailable.join(", ")),
                "severity": "warning",
            }));
        }

        // Check: providers without models
        let no_models: Vec<_> = config
            .providers
            .iter()
            .filter(|p| p.models.is_empty())
            .map(|p| p.name.clone())
            .collect();

        if !no_models.is_empty() {
            reasons.push(json!({
                "code": "providers_no_models",
                "message": format!("Providers with no models: {}", no_models.join(", ")),
                "severity": "warning",
            }));
        }

        let has_errors = reasons.iter().any(|r| {
            r.get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("error")
                == "error"
        });

        let ready = !has_errors;
        let status = if has_errors {
            "failed"
        } else if reasons.is_empty() {
            "ok"
        } else {
            "degraded"
        };

        Ok(json!({
            "ready": ready,
            "status": status,
            "reasons": reasons,
            "details": {
                "provider_count": config.providers.len(),
                "providers": readiness,
                "budget_usd": config.budget.budget_usd,
                "default_strategy": format!("{:?}", config.default_strategy).to_lowercase(),
            },
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let operations = vec![
            OperationInfo {
                id: OperationId::from_static("llm-router.route"),
                summary: "Select a provider/model and return a routing decision".to_string(),
                description: None,
                input_schema: Self::operation_input_schema("llm-router.route").unwrap_or(json!({})),
                output_schema: Self::operation_output_schema("llm-router.route")
                    .unwrap_or(json!({})),
                capability: CapabilityId::from_static("llm-router.route"),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
            OperationInfo {
                id: OperationId::from_static("llm-router.estimate_cost"),
                summary: "Estimate cost across providers without executing".to_string(),
                description: None,
                input_schema: Self::operation_input_schema("llm-router.estimate_cost")
                    .unwrap_or(json!({})),
                output_schema: Self::operation_output_schema("llm-router.estimate_cost")
                    .unwrap_or(json!({})),
                capability: CapabilityId::from_static("llm-router.route"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
            OperationInfo {
                id: OperationId::from_static("llm-router.list_providers"),
                summary: "List configured providers with health status".to_string(),
                description: None,
                input_schema: Self::operation_input_schema("llm-router.list_providers")
                    .unwrap_or(json!({})),
                output_schema: Self::operation_output_schema("llm-router.list_providers")
                    .unwrap_or(json!({})),
                capability: CapabilityId::from_static("llm-router.admin"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
            OperationInfo {
                id: OperationId::from_static("llm-router.get_usage"),
                summary: "Return session-level usage and cost totals".to_string(),
                description: None,
                input_schema: Self::operation_input_schema("llm-router.get_usage")
                    .unwrap_or(json!({})),
                output_schema: Self::operation_output_schema("llm-router.get_usage")
                    .unwrap_or(json!({})),
                capability: CapabilityId::from_static("llm-router.admin"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
            OperationInfo {
                id: OperationId::from_static("llm-router.get_budget"),
                summary: "Check remaining budget allocation".to_string(),
                description: None,
                input_schema: Self::operation_input_schema("llm-router.get_budget")
                    .unwrap_or(json!({})),
                output_schema: Self::operation_output_schema("llm-router.get_budget")
                    .unwrap_or(json!({})),
                capability: CapabilityId::from_static("llm-router.admin"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
        ];

        let introspection = Introspection {
            operations,
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    #[instrument(skip(self, params))]
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1002,
                    message: "Missing operation field".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let result = match operation {
            "llm-router.route" => {
                self.verify_capability(&params, "llm-router.route", operation)?;
                self.invoke_route(input).await
            }
            "llm-router.estimate_cost" => {
                self.verify_capability(&params, "llm-router.route", operation)?;
                self.invoke_estimate_cost(input).await
            }
            "llm-router.list_providers" => {
                self.verify_capability(&params, "llm-router.admin", operation)?;
                self.invoke_list_providers(input).await
            }
            "llm-router.get_usage" => {
                self.verify_capability(&params, "llm-router.admin", operation)?;
                self.invoke_get_usage(input).await
            }
            "llm-router.get_budget" => {
                self.verify_capability(&params, "llm-router.admin", operation)?;
                self.invoke_get_budget(input).await
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        };

        self.base.record_request(result.is_ok());

        result
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        Ok(json!({
            "operation": operation,
            "would_succeed": self.config.is_some(),
            "estimated_latency_ms": 500,
            "side_effects": [],
        }))
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("LLM Router shutting down");
        Ok(json!({
            "status": "shutdown",
            "total_cost_usd": self.total_cost(),
        }))
    }

    // -------------------------------------------------------------------------
    // Operation Implementations
    // -------------------------------------------------------------------------

    async fn invoke_route(&mut self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let config = self.config_ref()?.clone();

        let messages =
            input
                .get("messages")
                .and_then(|v| v.as_array())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing or invalid messages array".into(),
                })?;

        if messages.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "messages array must not be empty".into(),
            });
        }

        let strategy = input
            .get("strategy")
            .and_then(|v| v.as_str())
            .and_then(RoutingStrategy::from_str_opt)
            .unwrap_or(config.default_strategy);

        let preferred_provider = input.get("preferred_provider").and_then(|v| v.as_str());
        let preferred_model = input.get("preferred_model").and_then(|v| v.as_str());
        let budget_limit = input.get("budget_limit_usd").and_then(|v| v.as_f64());
        let max_tokens = input
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(4096);

        let required_caps: Vec<ModelCapability> = input
            .get("required_capabilities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(ModelCapability::from_str_opt)
                    .collect()
            })
            .unwrap_or_default();

        // Check budget enforcement
        if config.budget.enforcement == BudgetEnforcement::Hard {
            let spent = self.total_cost();
            if spent >= config.budget.budget_usd {
                return Err(RouterError::BudgetExceeded {
                    spent_usd: spent,
                    budget_usd: config.budget.budget_usd,
                }
                .into());
            }
        }

        // Estimate input tokens from message content
        let input_tokens: u64 = messages
            .iter()
            .filter_map(|m| m.get("content").and_then(|c| c.as_str()))
            .map(routing::estimate_tokens)
            .sum();

        // Build candidates and select
        let candidates = routing::build_candidates(
            &config.providers,
            &self.provider_status,
            input_tokens,
            max_tokens,
        );

        let (selected_idx, reason) = routing::select_candidate(
            &candidates,
            strategy,
            &required_caps,
            budget_limit,
            preferred_provider,
            preferred_model,
        )
        .map_err(|e| -> FcpError { e.into() })?;

        let selected = &candidates[selected_idx];
        let provider_name = &selected.provider_name;
        let model_id = &selected.model.id;

        info!(
            provider = %provider_name,
            model = %model_id,
            strategy = ?strategy,
            reason = %reason,
            "Routing decision made"
        );

        // The router returns a routing decision, not an LLM inference result.
        // The caller must separately invoke the chosen provider's connector
        // (FCP security invariant #3: no cross-connector calling).
        let cost = selected.estimated_cost;
        self.track_cost(cost);

        // Update provider usage
        let usage = self
            .provider_usage
            .entry(provider_name.clone())
            .or_default();
        usage.input_tokens += input_tokens;
        usage.output_tokens += max_tokens;
        usage.cost_usd += cost;
        usage.requests += 1;

        let routing_decision = RoutingDecision {
            strategy_used: format!("{strategy:?}").to_lowercase(),
            candidates_evaluated: u32::try_from(candidates.len()).unwrap_or(u32::MAX),
            fallback_used: strategy == RoutingStrategy::Fallback,
            reason,
        };

        Ok(json!({
            "dispatch_required": true,
            "dispatch_instruction": format!(
                "Invoke {provider_name}.chat_completion with model={model_id} to get the actual LLM response. \
                 This routing decision does not contain inference output."
            ),
            "provider": provider_name,
            "model": model_id,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": max_tokens
            },
            "cost_usd": cost,
            "routing_decision": routing_decision,
            "provenance": {
                "source": provider_name,
                "model": model_id,
                "integrity": "untrusted",
                "has_tool_calls": false,
                "chunk_count": 1,
                "taint": ["AI_GENERATED"]
            }
        }))
    }

    async fn invoke_estimate_cost(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let config = self.config_ref()?;

        let messages =
            input
                .get("messages")
                .and_then(|v| v.as_array())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing or invalid messages array".into(),
                })?;

        let max_tokens = input
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(4096);

        let filter_providers: Option<Vec<&str>> = input
            .get("providers")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect());

        let input_tokens: u64 = messages
            .iter()
            .filter_map(|m| m.get("content").and_then(|c| c.as_str()))
            .map(routing::estimate_tokens)
            .sum();

        let mut estimates: Vec<serde_json::Value> = Vec::new();

        for provider in &config.providers {
            if let Some(ref filter) = filter_providers {
                if !filter.contains(&provider.name.as_str()) {
                    continue;
                }
            }

            let status = self
                .provider_status
                .iter()
                .find(|(n, _, _)| n == &provider.name)
                .map(|(_, s, _)| *s)
                .unwrap_or(ProviderStatus::Healthy);

            for model in &provider.models {
                let cost = routing::estimate_cost(model, input_tokens, max_tokens);
                estimates.push(json!({
                    "provider": provider.name,
                    "model": model.id,
                    "estimated_cost_usd": cost,
                    "estimated_input_tokens": input_tokens,
                    "available": status != ProviderStatus::Unavailable,
                }));
            }
        }

        // Sort by cost ascending
        estimates.sort_by(|a, b| {
            let cost_a = a
                .get("estimated_cost_usd")
                .and_then(|v| v.as_f64())
                .unwrap_or(f64::MAX);
            let cost_b = b
                .get("estimated_cost_usd")
                .and_then(|v| v.as_f64())
                .unwrap_or(f64::MAX);
            cost_a
                .partial_cmp(&cost_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let recommended = estimates
            .iter()
            .find(|e| {
                e.get("available")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            })
            .cloned();

        Ok(json!({
            "estimates": estimates,
            "recommended": recommended,
        }))
    }

    async fn invoke_list_providers(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = self.config_ref()?;
        let include_models = input
            .get("include_models")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let providers: Vec<serde_json::Value> = config
            .providers
            .iter()
            .map(|p| {
                let (status, latency) = self
                    .provider_status
                    .iter()
                    .find(|(n, _, _)| n == &p.name)
                    .map(|(_, s, l)| (*s, *l))
                    .unwrap_or((ProviderStatus::Healthy, 0));

                let capabilities: Vec<String> = p
                    .models
                    .iter()
                    .flat_map(|m| m.capabilities.iter())
                    .map(|c| format!("{c:?}").to_lowercase())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                let mut entry = json!({
                    "name": p.name,
                    "status": status,
                    "capabilities": capabilities,
                    "latency_p50_ms": latency,
                    "passthrough_provider_models": p.passthrough_provider_models,
                    "image_generation_provider": p.image_generation_provider,
                });

                if include_models {
                    let models: Vec<serde_json::Value> = p
                        .models
                        .iter()
                        .map(|m| {
                            json!({
                                "id": m.id,
                                "context_window": m.context_window,
                                "capabilities": m.capabilities,
                                "cost_per_input_token": m.cost_per_input_token,
                                "cost_per_output_token": m.cost_per_output_token,
                            })
                        })
                        .collect();
                    entry["models"] = json!(models);
                }

                entry
            })
            .collect();

        Ok(json!({
            "providers": providers,
        }))
    }

    async fn invoke_get_usage(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let group_by = input
            .get("group_by")
            .and_then(|v| v.as_str())
            .unwrap_or("none");

        let total_input: u64 = self.provider_usage.values().map(|u| u.input_tokens).sum();
        let total_output: u64 = self.provider_usage.values().map(|u| u.output_tokens).sum();
        let total_requests: u64 = self.provider_usage.values().map(|u| u.requests).sum();
        let total_errors: u64 = self.provider_usage.values().map(|u| u.errors).sum();

        let mut result = json!({
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_cost_usd": self.total_cost(),
            "requests_total": total_requests,
            "requests_error": total_errors,
        });

        if group_by == "provider" {
            let breakdown: Vec<serde_json::Value> = self
                .provider_usage
                .iter()
                .map(|(name, usage)| {
                    json!({
                        "key": name,
                        "input_tokens": usage.input_tokens,
                        "output_tokens": usage.output_tokens,
                        "cost_usd": usage.cost_usd,
                        "requests": usage.requests,
                    })
                })
                .collect();
            result["breakdown"] = json!(breakdown);
        }

        Ok(result)
    }

    async fn invoke_get_budget(&self, _input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let config = self.config_ref()?;
        let spent = self.total_cost();
        let remaining = (config.budget.budget_usd - spent).max(0.0);

        Ok(json!({
            "budget_usd": config.budget.budget_usd,
            "spent_usd": spent,
            "remaining_usd": remaining,
            "enforcement": config.budget.enforcement,
            "period": config.budget.period,
            "alerts": [],
        }))
    }

    // -------------------------------------------------------------------------
    // Parsing helpers
    // -------------------------------------------------------------------------

    fn parse_providers(params: &serde_json::Value) -> FcpResult<Vec<ProviderConfig>> {
        let providers_val =
            params
                .get("providers")
                .and_then(|v| v.as_array())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing providers array in configuration".into(),
                })?;

        let mut providers = Vec::new();
        for (idx, pv) in providers_val.iter().enumerate() {
            let name = pv
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("providers[{idx}]: missing name"),
                })?
                .to_string();
            let descriptor = gateway_provider_descriptor(&name);

            let credential_id = pv
                .get("credential_id")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(String::from);

            let direct_auth = pv
                .get("api_key")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(String::from);

            let auth = match (direct_auth, credential_id) {
                (Some(key), None) => {
                    let auth = ProviderAuth::ApiKey(key);
                    auth.bearer_authorization_header().map_err(|error| {
                        FcpError::InvalidRequest {
                            code: 1003,
                            message: format!(
                                "providers[{idx}] ({name}): api_key must be a valid HTTP Authorization header value: {error}"
                            ),
                        }
                    })?;
                    auth
                }
                (None, Some(cid)) => ProviderAuth::CredentialId(cid),
                (Some(_), Some(_)) => {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: format!(
                            "providers[{idx}] ({name}): provide exactly one of api_key or credential_id, not both"
                        ),
                    });
                }
                (None, None) => {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: format!(
                            "providers[{idx}] ({name}): missing api_key or credential_id"
                        ),
                    });
                }
            };

            let (
                base_url,
                api_path_mode,
                extra_headers,
                passthrough_provider_models,
                image_generation_provider,
            ) = match descriptor.map(|d| d.endpoint) {
                Some(GatewayEndpoint::CloudflareAiGateway { provider_path, .. }) => {
                    if pv
                        .get("base_url")
                        .and_then(|v| v.as_str())
                        .is_some_and(|url| !url.trim().is_empty())
                    {
                        return Err(Self::provider_config_error(
                            idx,
                            &name,
                            "Cloudflare AI Gateway base_url is built from account_id and gateway_id; omit base_url",
                        ));
                    }

                    let configured_provider_path = pv
                        .get("provider_path")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or(provider_path);
                    if configured_provider_path != provider_path {
                        return Err(Self::provider_config_error(
                            idx,
                            &name,
                            format!("provider_path must be '{provider_path}'"),
                        ));
                    }

                    let account_id = Self::required_provider_string(pv, idx, &name, "account_id")?;
                    let gateway_id = Self::required_provider_string(pv, idx, &name, "gateway_id")?;
                    let descriptor = descriptor.expect("descriptor present for endpoint match");
                    let base_url = descriptor
                        .endpoint
                        .cloudflare_base_url(account_id, gateway_id)
                        .map_err(|error| {
                            Self::provider_config_error(
                                idx,
                                &name,
                                format!(
                                    "invalid account_id/gateway_id for Cloudflare AI Gateway: {error}"
                                ),
                            )
                        })?;
                    (
                        base_url,
                        ProviderApiPathMode::OpenAiCompatibleBase,
                        Self::cloudflare_gateway_headers(pv, idx, &name)?,
                        descriptor.passthrough_provider_models,
                        descriptor.image_generation_provider,
                    )
                }
                Some(GatewayEndpoint::FixedOpenAiCompatible {
                    base_url,
                    api_path_mode,
                    ..
                }) => {
                    if let Some(provided_base_url) = pv
                        .get("base_url")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|url| !url.is_empty())
                    {
                        let normalized = provided_base_url.trim_end_matches('/');
                        if normalized != base_url.trim_end_matches('/') {
                            return Err(Self::provider_config_error(
                                idx,
                                &name,
                                "fixed gateway-provider descriptors do not accept base_url overrides",
                            ));
                        }
                    }
                    let descriptor = descriptor.expect("descriptor present for endpoint match");
                    (
                        base_url.to_string(),
                        api_path_mode,
                        Vec::new(),
                        descriptor.passthrough_provider_models,
                        descriptor.image_generation_provider,
                    )
                }
                Some(GatewayEndpoint::OperatorConfiguredOpenAiCompatible) => {
                    let descriptor = descriptor.expect("descriptor present for endpoint match");
                    let (base_url, api_path_mode) =
                        Self::operator_configured_gateway_base_url(pv, idx, &name)?;
                    (
                        base_url,
                        api_path_mode,
                        Vec::new(),
                        descriptor.passthrough_provider_models,
                        descriptor.image_generation_provider,
                    )
                }
                None => {
                    let descriptor_metadata = descriptor
                        .map(|descriptor| {
                            (
                                descriptor.passthrough_provider_models,
                                descriptor.image_generation_provider,
                            )
                        })
                        .unwrap_or((false, false));
                    (
                        pv.get("base_url")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        ProviderApiPathMode::AppendV1,
                        Vec::new(),
                        descriptor_metadata.0,
                        descriptor_metadata.1,
                    )
                }
            };

            let priority = pv
                .get("priority")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or_else(|| u32::try_from(idx + 1).unwrap_or(u32::MAX));

            let mut models: Vec<ModelInfo> = pv
                .get("models")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| serde_json::from_value::<ModelInfo>(m.clone()).ok())
                        .collect()
                })
                .unwrap_or_default();
            if let Some(descriptor) = descriptor {
                for model in &mut models {
                    model.id = descriptor.normalize_model_id(&model.id);
                }
            }

            providers.push(ProviderConfig {
                name,
                base_url,
                auth,
                api_path_mode,
                extra_headers,
                models,
                priority,
                passthrough_provider_models,
                image_generation_provider,
            });
        }

        Ok(providers)
    }

    fn provider_config_error(idx: usize, name: &str, message: impl Into<String>) -> FcpError {
        FcpError::InvalidRequest {
            code: 1003,
            message: format!("providers[{idx}] ({name}): {}", message.into()),
        }
    }

    fn required_provider_string<'a>(
        provider: &'a serde_json::Value,
        idx: usize,
        name: &str,
        field: &'static str,
    ) -> FcpResult<&'a str> {
        provider
            .get(field)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Self::provider_config_error(idx, name, format!("missing {field}")))
    }

    fn cloudflare_gateway_headers(
        provider: &serde_json::Value,
        idx: usize,
        name: &str,
    ) -> FcpResult<Vec<ProviderHttpHeader>> {
        let Some(secret) = provider
            .get("cloudflare_gateway_api_key")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(Vec::new());
        };

        let header =
            ProviderHttpHeader::cloudflare_ai_gateway_authorization(secret).map_err(|error| {
                Self::provider_config_error(
                    idx,
                    name,
                    format!(
                        "cloudflare_gateway_api_key must be a valid HTTP header value: {error}"
                    ),
                )
            })?;
        Ok(vec![header])
    }

    fn operator_configured_gateway_base_url(
        provider: &serde_json::Value,
        idx: usize,
        name: &str,
    ) -> FcpResult<(String, ProviderApiPathMode)> {
        let raw_base_url = Self::required_provider_string(provider, idx, name, "base_url")?;
        let normalized = raw_base_url.trim_end_matches('/');
        let parsed = Url::parse(normalized).map_err(|error| {
            Self::provider_config_error(
                idx,
                name,
                format!("operator-configured gateway base_url is not a valid URL: {error}"),
            )
        })?;

        if !Self::operator_configured_gateway_url_allowed(&parsed) {
            return Err(Self::provider_config_error(
                idx,
                name,
                "operator-configured gateway base_url must be an HTTPS public DNS URL on port 443 with no userinfo, IP literal, query, or fragment",
            ));
        }

        let Some(api_path_mode) = Self::operator_gateway_path_mode(&parsed) else {
            return Err(Self::provider_config_error(
                idx,
                name,
                "operator-configured gateway base_url path must be empty or /v1",
            ));
        };

        Ok((normalized.to_string(), api_path_mode))
    }

    fn operator_gateway_path_mode(parsed: &Url) -> Option<ProviderApiPathMode> {
        match parsed.path().trim_end_matches('/') {
            "" => Some(ProviderApiPathMode::AppendV1),
            "/v1" => Some(ProviderApiPathMode::OpenAiCompatibleBase),
            _ => None,
        }
    }

    fn operator_configured_gateway_url_allowed(parsed: &Url) -> bool {
        if parsed.scheme() != "https"
            || parsed.port_or_known_default() != Some(443)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return false;
        }

        let Some(Host::Domain(host)) = parsed.host() else {
            return false;
        };
        Self::public_dns_host_allowed(host)
    }

    fn public_dns_host_allowed(host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = host.split('.').collect();
        if host.is_empty()
            || labels
                .last()
                .is_some_and(|label| matches!(*label, "localhost" | "local"))
        {
            return false;
        }

        labels.len() >= 2
            && labels.iter().all(|label| {
                let bytes = label.as_bytes();
                !bytes.is_empty()
                    && bytes.len() <= 63
                    && bytes[0].is_ascii_alphanumeric()
                    && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                    && bytes
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            })
    }

    fn parse_budget(params: &serde_json::Value) -> BudgetConfig {
        let budget_obj = params.get("budget");
        match budget_obj {
            Some(b) => BudgetConfig {
                budget_usd: b
                    .get("budget_usd")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(f64::INFINITY),
                enforcement: b
                    .get("enforcement")
                    .and_then(|v| v.as_str())
                    .map(|s| match s {
                        "hard" => BudgetEnforcement::Hard,
                        "soft" => BudgetEnforcement::Soft,
                        _ => BudgetEnforcement::None,
                    })
                    .unwrap_or_default(),
                period: b
                    .get("period")
                    .and_then(|v| v.as_str())
                    .unwrap_or("session")
                    .to_string(),
            },
            None => BudgetConfig::default(),
        }
    }

    /// Check if a provider's `base_url` is within the LLM Router's allowed hosts.
    fn host_allowed(base_url: &str) -> bool {
        let Ok(parsed) = Url::parse(base_url.trim()) else {
            return false;
        };
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return false;
        }

        let Some(host) = parsed
            .host_str()
            .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        else {
            return false;
        };
        let is_localhost = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]");

        // Allow localhost for test infrastructure.
        if (cfg!(test) || cfg!(feature = "testing")) && is_localhost {
            return matches!(parsed.scheme(), "http" | "https");
        }

        parsed.scheme() == "https"
            && parsed.port_or_known_default() == Some(443)
            && llm_router_host_is_allowed(host.as_str())
    }

    fn provider_host_allowed(provider: &ProviderConfig) -> bool {
        if gateway_provider_descriptor(&provider.name).is_some_and(|descriptor| {
            matches!(
                descriptor.endpoint,
                GatewayEndpoint::OperatorConfiguredOpenAiCompatible
            )
        }) {
            let Ok(parsed) = Url::parse(provider.base_url.trim()) else {
                return false;
            };
            return Self::operator_configured_gateway_url_allowed(&parsed)
                && Self::operator_gateway_path_mode(&parsed).is_some();
        }

        Self::host_allowed(&provider.base_url)
    }

    fn reserved_gateway_host_owners(base_url: &str) -> Vec<&'static str> {
        let Some(host) = Url::parse(base_url.trim()).ok().and_then(|parsed| {
            parsed
                .host_str()
                .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        }) else {
            return Vec::new();
        };
        built_in_gateway_provider_descriptors()
            .iter()
            .filter(|descriptor| {
                descriptor
                    .endpoint
                    .static_host()
                    .is_some_and(|allowed| allowed == host.as_str())
            })
            .map(|descriptor| descriptor.id)
            .collect()
    }

    /// Build per-provider provisioning readiness.
    fn provider_readiness(providers: &[ProviderConfig]) -> Vec<ProviderReadiness> {
        providers
            .iter()
            .map(|p| {
                let auth_ok = match &p.auth {
                    ProviderAuth::ApiKey(key) => !key.is_empty(),
                    ProviderAuth::CredentialId(cid) => !cid.is_empty(),
                };
                let auth_mode = match &p.auth {
                    ProviderAuth::ApiKey(_) => "api_key",
                    ProviderAuth::CredentialId(_) => "credential_id",
                };
                let network_ok = Self::provider_host_allowed(p);
                let models_ok = !p.models.is_empty();

                ProviderReadiness {
                    name: p.name.clone(),
                    auth_ok,
                    auth_mode: auth_mode.into(),
                    network_ok,
                    models_ok,
                    model_count: p.models.len(),
                }
            })
            .collect()
    }

    /// Validate all providers pass network constraint checks.
    fn validate_network_constraints(providers: &[ProviderConfig]) -> FcpResult<()> {
        for p in providers {
            if !Self::provider_host_allowed(p) {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Provider '{}' base_url '{}' violates NetworkConstraints",
                        p.name, p.base_url
                    ),
                });
            }
            let owners = Self::reserved_gateway_host_owners(&p.base_url);
            if !owners.is_empty() && !owners.iter().any(|owner| *owner == p.name) {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Provider '{}' base_url '{}' uses gateway host reserved for descriptor(s) '{}'",
                        p.name,
                        p.base_url,
                        owners.join(", ")
                    ),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{CapabilityConstraints, InstanceId};

    fn test_config_params() -> serde_json::Value {
        json!({
            "providers": [
                {
                    "name": "anthropic",
                    "base_url": "https://api.anthropic.com",
                    "api_key": "test-key-1",
                    "priority": 1,
                    "models": [
                        {
                            "id": "claude-sonnet-4",
                            "capabilities": ["code", "tool_use"],
                            "context_window": 200000,
                            "cost_per_input_token": 0.000003,
                            "cost_per_output_token": 0.000015
                        }
                    ]
                },
                {
                    "name": "openai",
                    "base_url": "https://api.openai.com",
                    "api_key": "test-key-2",
                    "priority": 2,
                    "models": [
                        {
                            "id": "gpt-4o",
                            "capabilities": ["code", "vision", "tool_use"],
                            "context_window": 128000,
                            "cost_per_input_token": 0.000005,
                            "cost_per_output_token": 0.000015
                        }
                    ]
                }
            ],
            "default_strategy": "cost",
            "budget": {
                "budget_usd": 10.0,
                "enforcement": "hard",
                "period": "session"
            }
        })
    }

    fn signed_token(
        signing_key: &Ed25519SigningKey,
        capability: &str,
        operation: &str,
        instance_id: &str,
    ) -> CapabilityToken {
        let now = chrono::Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("test constraints CBOR should be valid")
            .sign(signing_key)
            .expect("test token signing should succeed");
        CapabilityToken::from_raw(raw)
    }

    #[fcp_async_core::runtime::test]
    async fn configure_succeeds() {
        let mut connector = LlmRouterConnector::new();
        let result = connector.handle_configure(test_config_params()).await;
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val["status"], "configured");
        assert_eq!(val["providers"].as_array().unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn configure_requires_providers() {
        let mut connector = LlmRouterConnector::new();
        let result = connector.handle_configure(json!({"providers": []})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_before_configure() {
        let connector = LlmRouterConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "unconfigured");
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_returns_all_operations() {
        let connector = LlmRouterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 5);

        let op_ids: Vec<&str> = ops
            .iter()
            .filter_map(|o| o.get("id").and_then(|v| v.as_str()))
            .collect();
        assert!(op_ids.contains(&"llm-router.route"));
        assert!(op_ids.contains(&"llm-router.estimate_cost"));
        assert!(op_ids.contains(&"llm-router.list_providers"));
        assert!(op_ids.contains(&"llm-router.get_usage"));
        assert!(op_ids.contains(&"llm-router.get_budget"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_route_without_configure_fails() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.route",
                "capability_token": "test",
                "input": {"messages": [{"role": "user", "content": "hello"}]}
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn list_providers_after_configure() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.list_providers",
                "capability_token": "test",
                "input": {"include_models": true}
            }))
            .await
            .unwrap();

        let providers = result["providers"].as_array().unwrap();
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0]["name"], "anthropic");
        assert!(providers[0]["models"].as_array().is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_with_real_token_checks_actual_operation_id() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let instance_id = InstanceId::new();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "requested_instance_id": instance_id.clone(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["llm-router.admin"]
            }))
            .await
            .expect("handshake should succeed");

        let admin_capability = signed_token(
            &signing_key,
            "llm-router.admin",
            "llm-router.get_budget",
            instance_id.as_str(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.get_budget",
                "capability_token": admin_capability,
                "input": {}
            }))
            .await
            .expect("operation-specific admin token should be accepted");

        assert_eq!(result["enforcement"], "hard");
    }

    #[fcp_async_core::runtime::test]
    async fn estimate_cost_returns_sorted() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.estimate_cost",
                "capability_token": "test",
                "input": {
                    "messages": [{"role": "user", "content": "Hello world, how are you today?"}]
                }
            }))
            .await
            .unwrap();

        let estimates = result["estimates"].as_array().unwrap();
        assert_eq!(estimates.len(), 2);
        // Should be sorted by cost ascending
        let cost_0 = estimates[0]["estimated_cost_usd"].as_f64().unwrap();
        let cost_1 = estimates[1]["estimated_cost_usd"].as_f64().unwrap();
        assert!(cost_0 <= cost_1);
    }

    #[fcp_async_core::runtime::test]
    async fn get_usage_initially_zero() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.get_usage",
                "capability_token": "test",
                "input": {}
            }))
            .await
            .unwrap();

        assert_eq!(result["total_input_tokens"], 0);
        assert_eq!(result["total_output_tokens"], 0);
        assert_eq!(result["requests_total"], 0);
    }

    #[fcp_async_core::runtime::test]
    async fn get_budget_reflects_config() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.get_budget",
                "capability_token": "test",
                "input": {}
            }))
            .await
            .unwrap();

        assert_eq!(result["budget_usd"], 10.0);
        assert_eq!(result["spent_usd"], 0.0);
        assert_eq!(result["remaining_usd"], 10.0);
        assert_eq!(result["enforcement"], "hard");
    }

    #[fcp_async_core::runtime::test]
    async fn route_selects_provider_and_tracks_usage() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.route",
                "capability_token": "test",
                "input": {
                    "messages": [{"role": "user", "content": "Hello"}],
                    "strategy": "cost"
                }
            }))
            .await
            .unwrap();

        // The router returns a routing decision, not an LLM response.
        assert!(result.get("dispatch_required").is_some());
        assert!(result.get("dispatch_instruction").is_some());
        assert!(result.get("provider").is_some());
        assert!(result.get("model").is_some());
        assert!(result.get("routing_decision").is_some());
        assert!(result.get("provenance").is_some());
        assert!(result.get("cost_usd").is_some());

        // Verify provenance
        let provenance = &result["provenance"];
        assert_eq!(provenance["integrity"], "untrusted");
        assert!(
            provenance["taint"]
                .as_array()
                .unwrap()
                .contains(&json!("AI_GENERATED"))
        );

        // Verify usage was tracked
        let usage_result = connector
            .handle_invoke(json!({
                "operation": "llm-router.get_usage",
                "capability_token": "test",
                "input": {}
            }))
            .await
            .unwrap();

        assert!(usage_result["requests_total"].as_u64().unwrap() > 0);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_reports_healthy_after_configure() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_reports_ready() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["ready"], true);
        assert_eq!(result["status"], "ok");
        assert!(result["details"]["providers"].as_array().is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let connector = LlmRouterConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["ready"], false);
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_returns_provisioning_readiness() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        let provisioning = result["provisioning"].as_array().unwrap();
        assert_eq!(provisioning.len(), 2);

        for p in provisioning {
            assert_eq!(p["auth_ok"], true);
            assert_eq!(p["auth_mode"], "api_key");
            assert_eq!(p["network_ok"], true);
            assert_eq!(p["models_ok"], true);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_both_api_key_and_credential_id() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "name": "test",
                    "base_url": "https://api.anthropic.com",
                    "api_key": "key-123",
                    "credential_id": "cred-123",
                    "models": []
                }]
            }))
            .await;

        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_missing_auth() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "name": "test",
                    "base_url": "https://api.anthropic.com",
                    "models": []
                }]
            }))
            .await;

        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_accepts_credential_id() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "name": "anthropic",
                    "base_url": "https://api.anthropic.com",
                    "credential_id": "550e8400-e29b-41d4-a716-446655440000",
                    "models": [{
                        "id": "claude-sonnet-4",
                        "capabilities": ["code"],
                        "context_window": 200000,
                        "cost_per_input_token": 0.000003,
                        "cost_per_output_token": 0.000015
                    }]
                }]
            }))
            .await
            .unwrap();

        let provisioning = result["provisioning"].as_array().unwrap();
        assert_eq!(provisioning[0]["auth_mode"], "credential_id");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_reports_credential_injection() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(json!({
                "providers": [{
                    "name": "anthropic",
                    "base_url": "https://api.anthropic.com",
                    "credential_id": "550e8400-e29b-41d4-a716-446655440000",
                    "models": [{
                        "id": "claude-sonnet-4",
                        "capabilities": ["code"],
                        "context_window": 200000,
                        "cost_per_input_token": 0.000003,
                        "cost_per_output_token": 0.000015
                    }]
                }]
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["ready"], true);
        // Should note credential injection is required
        let reasons = result["reasons"].as_array().unwrap();
        let has_cred_info = reasons.iter().any(|r| {
            r.get("code").and_then(|v| v.as_str()) == Some("credential_injection_required")
        });
        assert!(has_cred_info);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_reports_detailed_checks() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");

        let checks = result["checks"].as_array().unwrap();
        let check_names: Vec<&str> = checks
            .iter()
            .filter_map(|c| c.get("name").and_then(|v| v.as_str()))
            .collect();

        assert!(check_names.contains(&"configuration"));
        assert!(check_names.contains(&"providers"));
        assert!(check_names.contains(&"network_constraints"));
        assert!(check_names.contains(&"credential_injection"));
        assert!(check_names.contains(&"budget"));
        assert!(check_names.contains(&"provider.anthropic"));
        assert!(check_names.contains(&"provider.openai"));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_unconfigured_is_unhealthy() {
        let connector = LlmRouterConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn auth_redacted_label() {
        let api_key_auth = ProviderAuth::ApiKey("sk-1234567890abcdef".into());
        let label = api_key_auth.redacted_label();
        assert_eq!(label, "api_key:[redacted]");
        assert!(!label.contains("sk-1234"));
        assert!(!label.contains("cdef"));

        let cred_auth = ProviderAuth::CredentialId("my-uuid".into());
        assert_eq!(cred_auth.redacted_label(), "credential_id:my-uuid");
    }

    // ---- Schema completeness tests ----

    #[test]
    fn all_operations_have_input_schema() {
        let ops = [
            "llm-router.route",
            "llm-router.estimate_cost",
            "llm-router.list_providers",
            "llm-router.get_usage",
            "llm-router.get_budget",
        ];
        for op in ops {
            let schema = LlmRouterConnector::operation_input_schema(op);
            assert!(schema.is_some(), "Missing input schema for {op}");
            let schema = schema.unwrap();
            assert_eq!(
                schema["type"], "object",
                "Input schema for {op} must be object type"
            );
        }
    }

    #[test]
    fn all_operations_have_output_schema() {
        let ops = [
            "llm-router.route",
            "llm-router.estimate_cost",
            "llm-router.list_providers",
            "llm-router.get_usage",
            "llm-router.get_budget",
        ];
        for op in ops {
            let schema = LlmRouterConnector::operation_output_schema(op);
            assert!(schema.is_some(), "Missing output schema for {op}");
            let schema = schema.unwrap();
            assert_eq!(
                schema["type"], "object",
                "Output schema for {op} must be object type"
            );
        }
    }

    #[test]
    fn unknown_operation_schema_is_none() {
        assert!(LlmRouterConnector::operation_input_schema("llm-router.nonexistent").is_none());
        assert!(LlmRouterConnector::operation_output_schema("llm-router.nonexistent").is_none());
        assert!(LlmRouterConnector::operation_input_schema("").is_none());
        assert!(LlmRouterConnector::operation_output_schema("").is_none());
    }

    #[test]
    fn schema_is_deterministic() {
        let ops = [
            "llm-router.route",
            "llm-router.estimate_cost",
            "llm-router.list_providers",
            "llm-router.get_usage",
            "llm-router.get_budget",
        ];
        for op in ops {
            let s1 = LlmRouterConnector::operation_input_schema(op).unwrap();
            let s2 = LlmRouterConnector::operation_input_schema(op).unwrap();
            assert_eq!(s1, s2, "Input schema for {op} is not deterministic");

            let o1 = LlmRouterConnector::operation_output_schema(op).unwrap();
            let o2 = LlmRouterConnector::operation_output_schema(op).unwrap();
            assert_eq!(o1, o2, "Output schema for {op} is not deterministic");
        }
    }

    #[test]
    fn route_output_schema_has_required_fields() {
        let schema = LlmRouterConnector::operation_output_schema("llm-router.route").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_strs.contains(&"dispatch_required"));
        assert!(required_strs.contains(&"dispatch_instruction"));
        assert!(required_strs.contains(&"provider"));
        assert!(required_strs.contains(&"model"));
        assert!(required_strs.contains(&"cost_usd"));
        assert!(required_strs.contains(&"routing_decision"));
        assert!(required_strs.contains(&"provenance"));
        assert!(
            !required_strs.contains(&"response"),
            "route output schema must not promise inference output"
        );
    }

    #[test]
    fn route_input_schema_requires_messages() {
        let schema = LlmRouterConnector::operation_input_schema("llm-router.route").unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("messages")));
    }

    #[test]
    fn get_budget_output_schema_has_required_fields() {
        let schema = LlmRouterConnector::operation_output_schema("llm-router.get_budget").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_strs.contains(&"budget_usd"));
        assert!(required_strs.contains(&"spent_usd"));
        assert!(required_strs.contains(&"remaining_usd"));
        assert!(required_strs.contains(&"enforcement"));
    }

    // ---- Network constraint tests ----

    #[test]
    fn host_allowed_accepts_valid_hosts() {
        assert!(LlmRouterConnector::host_allowed(
            "https://api.anthropic.com"
        ));
        assert!(LlmRouterConnector::host_allowed("https://api.openai.com"));
        assert!(LlmRouterConnector::host_allowed(
            "https://generativelanguage.googleapis.com"
        ));
        // With paths
        assert!(LlmRouterConnector::host_allowed(
            "https://api.anthropic.com/v1/messages"
        ));
        // With ports
        assert!(LlmRouterConnector::host_allowed(
            "https://api.openai.com:443"
        ));
    }

    #[test]
    fn host_allowed_rejects_invalid_hosts() {
        assert!(!LlmRouterConnector::host_allowed(
            "https://evil.example.com"
        ));
        assert!(!LlmRouterConnector::host_allowed(
            "https://api.competitor.io"
        ));
        assert!(!LlmRouterConnector::host_allowed(
            "https://phishing-openai.com"
        ));
        assert!(!LlmRouterConnector::host_allowed("http://api.openai.com"));
        assert!(!LlmRouterConnector::host_allowed(
            "https://api.openai.com:444"
        ));
        assert!(!LlmRouterConnector::host_allowed(
            "https://api.openai.com:443@evil.example.com/v1"
        ));
        assert!(!LlmRouterConnector::host_allowed(
            "https://api.openai.com/v1?proxy=evil"
        ));
        assert!(!LlmRouterConnector::host_allowed(
            "https://api.openai.com/v1#fragment"
        ));
        assert!(!LlmRouterConnector::host_allowed(""));
    }

    #[test]
    fn host_allowed_accepts_localhost_in_test() {
        // In #[cfg(test)], localhost should be allowed
        assert!(LlmRouterConnector::host_allowed("http://localhost:8080"));
        assert!(LlmRouterConnector::host_allowed("http://127.0.0.1:3000"));
        assert!(LlmRouterConnector::host_allowed("http://[::1]:3000"));
    }

    fn litellm_provider_for_url(base_url: &str) -> ProviderConfig {
        ProviderConfig {
            name: "litellm".into(),
            base_url: base_url.into(),
            auth: ProviderAuth::ApiKey("key".into()),
            api_path_mode: ProviderApiPathMode::AppendV1,
            extra_headers: Vec::new(),
            models: vec![ModelInfo {
                id: "openai/gpt-4o".into(),
                capabilities: vec![ModelCapability::Code],
                context_window: 128000,
                cost_per_input_token: 0.000005,
                cost_per_output_token: 0.000015,
            }],
            priority: 1,
            passthrough_provider_models: true,
            image_generation_provider: true,
        }
    }

    #[test]
    fn provider_host_allowed_accepts_litellm_public_https_root_and_v1() {
        for base_url in [
            "https://litellm.flywheel.dev",
            "https://litellm.flywheel.dev/v1",
            "https://gateway.operator.example.com/v1/",
        ] {
            let provider = litellm_provider_for_url(base_url);
            assert!(
                LlmRouterConnector::provider_host_allowed(&provider),
                "expected LiteLLM operator URL to pass: {base_url}"
            );
        }
    }

    #[test]
    fn provider_host_allowed_rejects_litellm_private_or_ambiguous_hosts() {
        for base_url in [
            "http://litellm.flywheel.dev",
            "https://localhost",
            "https://127.0.0.1",
            "https://10.0.0.1",
            "https://[fd00::1]",
            "https://litellm",
            "https://litellm.local",
            "https://user@litellm.flywheel.dev",
            "https://litellm.flywheel.dev:444",
            "https://litellm.flywheel.dev/proxy",
            "https://litellm.flywheel.dev/v1?proxy=1",
            "https://litellm.flywheel.dev/v1#fragment",
        ] {
            let provider = litellm_provider_for_url(base_url);
            assert!(
                !LlmRouterConnector::provider_host_allowed(&provider),
                "expected LiteLLM operator URL to fail: {base_url}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_network_constraint_violation() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "name": "evil",
                    "base_url": "https://evil.example.com",
                    "api_key": "key-123",
                    "models": []
                }]
            }))
            .await;
        assert!(result.is_err());
    }

    // ---- Simulate handler ----

    #[fcp_async_core::runtime::test]
    async fn simulate_returns_expected_format() {
        let connector = LlmRouterConnector::new();
        let result = connector
            .handle_simulate(json!({
                "operation": "llm-router.route"
            }))
            .await
            .unwrap();
        assert_eq!(result["operation"], "llm-router.route");
        assert_eq!(result["would_succeed"], false); // not configured
        assert!(result["estimated_latency_ms"].as_u64().is_some());
        assert!(result["side_effects"].as_array().unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_succeeds_when_configured() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();
        let result = connector
            .handle_simulate(json!({
                "operation": "llm-router.route"
            }))
            .await
            .unwrap();
        assert_eq!(result["would_succeed"], true);
    }

    // ---- Shutdown handler ----

    #[fcp_async_core::runtime::test]
    async fn shutdown_returns_zero_cost_before_routing() {
        let mut connector = LlmRouterConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
        assert_eq!(result["total_cost_usd"], 0.0);
    }

    // ---- Configure edge cases ----

    #[fcp_async_core::runtime::test]
    async fn configure_missing_providers_array() {
        let mut connector = LlmRouterConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_provider_missing_name() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "base_url": "https://api.anthropic.com",
                    "api_key": "key",
                    "models": []
                }]
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_default_strategy_when_missing() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "name": "anthropic",
                    "base_url": "https://api.anthropic.com",
                    "api_key": "key",
                    "models": []
                }]
            }))
            .await
            .unwrap();
        // default_strategy should default to cost (serde lowercase)
        assert_eq!(result["default_strategy"], "cost");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_default_budget_when_missing() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(json!({
                "providers": [{
                    "name": "anthropic",
                    "base_url": "https://api.anthropic.com",
                    "api_key": "key",
                    "models": []
                }]
            }))
            .await
            .unwrap();

        let budget = connector
            .handle_invoke(json!({
                "operation": "llm-router.get_budget",
                "capability_token": "test",
                "input": {}
            }))
            .await
            .unwrap();

        // Default budget is infinite — serialized as null in JSON
        assert!(
            budget["budget_usd"].is_null() || {
                budget["budget_usd"]
                    .as_f64()
                    .is_some_and(|v| v.is_infinite())
            }
        );
        assert_eq!(budget["enforcement"], "none");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_whitespace_only_api_key_rejected() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "name": "test",
                    "base_url": "https://api.anthropic.com",
                    "api_key": "   ",
                    "models": []
                }]
            }))
            .await;
        // Whitespace-only key should be treated as missing
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_header_unsafe_api_key_rejected() {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "name": "test",
                    "base_url": "https://api.anthropic.com",
                    "api_key": "sk-valid\r\nx-injected: bad",
                    "models": []
                }]
            }))
            .await;
        let err = result.unwrap_err().to_string();
        assert!(err.contains("valid HTTP Authorization header value"));
        assert!(!err.contains("sk-valid"));
        assert!(!err.contains("x-injected"));
    }

    // ---- Invoke edge cases ----

    #[fcp_async_core::runtime::test]
    async fn invoke_missing_operation_field() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "capability_token": "test",
                "input": {}
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_missing_capability_token() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.route",
                "input": {"messages": [{"role": "user", "content": "hi"}]}
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_invalid_capability_token_format() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.route",
                "capability_token": 12345,
                "input": {"messages": [{"role": "user", "content": "hi"}]}
            }))
            .await;
        assert!(result.is_err());
    }

    // ---- Usage tracking ----

    #[fcp_async_core::runtime::test]
    async fn usage_with_provider_breakdown() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        // Route a request to generate usage
        connector
            .handle_invoke(json!({
                "operation": "llm-router.route",
                "capability_token": "test",
                "input": {
                    "messages": [{"role": "user", "content": "Hello world"}],
                    "strategy": "cost"
                }
            }))
            .await
            .unwrap();

        // Get usage with provider breakdown
        let usage = connector
            .handle_invoke(json!({
                "operation": "llm-router.get_usage",
                "capability_token": "test",
                "input": {"group_by": "provider"}
            }))
            .await
            .unwrap();

        assert!(usage["requests_total"].as_u64().unwrap() > 0);
        assert!(usage["breakdown"].as_array().is_some());
        let breakdown = usage["breakdown"].as_array().unwrap();
        assert!(!breakdown.is_empty());
    }

    // ---- Health after configure ----

    #[fcp_async_core::runtime::test]
    async fn health_after_configure_reports_ok() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["configured"], true);
    }

    // ---- List providers without models ----

    #[fcp_async_core::runtime::test]
    async fn list_providers_no_models_flag() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(test_config_params())
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "llm-router.list_providers",
                "capability_token": "test",
                "input": {}  // include_models defaults to false
            }))
            .await
            .unwrap();

        let providers = result["providers"].as_array().unwrap();
        // Without include_models flag, no "models" key expected
        assert!(providers[0].get("models").is_none());
    }

    // ---- Self-check with network violation ----

    #[fcp_async_core::runtime::test]
    async fn self_check_reports_no_models_warning() {
        let mut connector = LlmRouterConnector::new();
        connector
            .handle_configure(json!({
                "providers": [{
                    "name": "anthropic",
                    "base_url": "https://api.anthropic.com",
                    "api_key": "key",
                    "models": []  // No models
                }]
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let reasons = result["reasons"].as_array().unwrap();
        let has_no_models = reasons
            .iter()
            .any(|r| r.get("code").and_then(|v| v.as_str()) == Some("providers_no_models"));
        assert!(has_no_models);
    }
}
