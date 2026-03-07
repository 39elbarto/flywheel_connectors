//! Discovery-driven generation artifacts for Google connectors.
//!
//! This module derives three synchronized outputs from the same pinned
//! Discovery + policy substrate:
//! - FCP introspection operations (`fcp_core::Introspection`)
//! - MCP-oriented tool descriptors
//! - agent skill artifacts
//!
//! The goal is to eliminate parallel hand-maintained tool/skill metadata.

use std::collections::{BTreeMap, BTreeSet};

use fcp_core::{
    AgentHint, ApprovalMode, CapabilityId, EventInfo, IdValidationError, IdempotencyClass,
    Introspection, OperationId, OperationInfo, ResourceTypeInfo, RiskLevel, SafetyTier,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    DiscoveryMethod, DiscoveryParameter, DiscoverySchema, DiscoverySnapshot,
    policy::{
        GoogleOperationPolicyRule, GooglePolicyCatalog, GoogleServicePolicy, PolicyApprovalMode,
        PolicyRiskLevel, PolicySafetyTier,
    },
};

const MAX_SCHEMA_RENDER_DEPTH: usize = 64;

/// Errors emitted by Discovery-to-artifact generation.
#[derive(Debug, thiserror::Error)]
pub enum GoogleGenerationError {
    /// No service-level policy entry exists for this service.
    #[error("missing policy profile for service `{service}`")]
    MissingServicePolicy {
        /// Canonical Discovery service name.
        service: String,
    },

    /// Operation key could not be classified under service policy.
    #[error("no policy rule matched `{service}.{operation_key}`")]
    UnclassifiedOperation {
        /// Canonical Discovery service name.
        service: String,
        /// Discovery method key.
        operation_key: String,
    },

    /// Generated capability id is not canonical.
    #[error("invalid generated capability id `{capability}`: {source}")]
    InvalidCapabilityId {
        /// Generated capability id.
        capability: String,
        /// Canonical-id validation error.
        source: IdValidationError,
    },

    /// Generated operation id is not canonical.
    #[error("invalid generated operation id `{operation_id}`: {source}")]
    InvalidOperationId {
        /// Generated operation id.
        operation_id: String,
        /// Canonical-id validation error.
        source: IdValidationError,
    },
}

/// Full artifact bundle derived from one normalized Discovery snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleGeneratedArtifacts {
    /// Canonical service identity (`api_name:api_version`).
    pub service_identity: String,
    /// FCP introspection output.
    pub introspection: Introspection,
    /// MCP-facing tool descriptors.
    pub mcp_tools: Vec<GoogleMcpToolDescriptor>,
    /// Agent skill artifacts derived from the same operation substrate.
    pub agent_skills: Vec<GoogleAgentSkillArtifact>,
    /// Manifest operation fragments derived from the same operation substrate.
    pub manifest_fragment: GoogleManifestFragment,
}

impl GoogleGeneratedArtifacts {
    /// Number of generated operations (identical across generated views).
    #[must_use]
    pub fn operation_count(&self) -> usize {
        self.introspection.operations.len()
    }
}

/// MCP-oriented descriptor generated from Discovery + policy metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleMcpToolDescriptor {
    /// Tool name (operation id).
    pub name: String,
    /// Human-readable summary/description.
    pub description: String,
    /// JSON schema for tool input.
    pub input_schema: Value,
    /// JSON schema for tool output.
    pub output_schema: Value,
    /// Required capability.
    pub capability: CapabilityId,
    /// Risk level for planning/UX.
    pub risk_level: RiskLevel,
    /// Safety tier for enforcement.
    pub safety_tier: SafetyTier,
    /// Idempotency behavior.
    pub idempotency: IdempotencyClass,
    /// Optional approval mode requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalMode>,
    /// Whether the tool requires confirmation.
    pub requires_confirmation: bool,
    /// Whether simulate/preflight is expected to be supported.
    pub supports_simulate: bool,
    /// Required OAuth scopes from method + policy union.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
    /// Policy notes that informed generation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_notes: Vec<String>,
    /// Optional AI hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_hints: Option<AgentHint>,
}

/// Agent skill artifact generated from the same operation substrate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleAgentSkillArtifact {
    /// Stable skill identifier.
    pub skill_id: String,
    /// Associated tool/operation name.
    pub tool_name: String,
    /// Human-facing display name.
    pub display_name: String,
    /// Short summary.
    pub summary: String,
    /// Guidance for when to use this skill/tool.
    pub when_to_use: String,
    /// Required capability identifier.
    pub required_capability: String,
    /// Risk level.
    pub risk_level: RiskLevel,
    /// Optional approval mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalMode>,
    /// Required OAuth scopes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
    /// Recommended deployment zones for this service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommended_zones: Vec<String>,
    /// Default host allowlist hints from service policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_allow: Vec<String>,
    /// Additional rule/service notes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Generated manifest fragment derived from Discovery + policy metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleManifestFragment {
    /// Canonical connector id derived from service identity.
    pub connector_id: String,
    /// Generated operation fragments for manifest embedding.
    pub operations: Vec<GoogleManifestOperationFragment>,
}

/// Generated manifest operation entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleManifestOperationFragment {
    /// Canonical operation id.
    pub operation_id: String,
    /// Summary/description line.
    pub summary: String,
    /// Optional long description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Input schema.
    pub input_schema: Value,
    /// Output schema.
    pub output_schema: Value,
    /// Capability id.
    pub capability: String,
    /// Risk level.
    pub risk_level: RiskLevel,
    /// Safety tier.
    pub safety_tier: SafetyTier,
    /// Idempotency class.
    pub idempotency: IdempotencyClass,
    /// Optional approval requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalMode>,
    /// Explicit confirm requirement.
    pub requires_confirmation: bool,
    /// Supports simulate/preflight.
    pub supports_simulate: bool,
    /// Required OAuth scopes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
    /// Policy notes for operators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_notes: Vec<String>,
}

/// Generate synchronized introspection, MCP, skill, and manifest artifacts from one snapshot.
///
/// # Errors
///
/// Returns [`GoogleGenerationError`] for missing policy mappings or invalid generated
/// identifiers.
pub fn generate_google_service_artifacts(
    snapshot: &DiscoverySnapshot,
    policy_catalog: &GooglePolicyCatalog,
) -> Result<GoogleGeneratedArtifacts, GoogleGenerationError> {
    let service_policy = policy_catalog
        .service(&snapshot.service.api_name)
        .ok_or_else(|| GoogleGenerationError::MissingServicePolicy {
            service: snapshot.service.api_name.clone(),
        })?;

    let mut operations = Vec::with_capacity(snapshot.methods.len());
    let mut mcp_tools = Vec::with_capacity(snapshot.methods.len());
    let mut agent_skills = Vec::with_capacity(snapshot.methods.len());
    let mut manifest_operations = Vec::with_capacity(snapshot.methods.len());

    for method in snapshot.methods.values() {
        let resolved = policy_catalog
            .classify_operation(&snapshot.service.api_name, &method.key)
            .ok_or_else(|| GoogleGenerationError::UnclassifiedOperation {
                service: snapshot.service.api_name.clone(),
                operation_key: method.key.clone(),
            })?;

        let operation_id_string =
            build_operation_id_string(&snapshot.service.api_name, &method.key);
        let operation_id = OperationId::new(operation_id_string.clone()).map_err(|source| {
            GoogleGenerationError::InvalidOperationId {
                operation_id: operation_id_string.clone(),
                source,
            }
        })?;

        let capability = CapabilityId::new(resolved.rule.capability.clone()).map_err(|source| {
            GoogleGenerationError::InvalidCapabilityId {
                capability: resolved.rule.capability.clone(),
                source,
            }
        })?;

        let approval_mode = map_policy_approval_mode(resolved.rule.approval_mode);
        let risk_level = map_policy_risk_level(resolved.rule.risk_level);
        let safety_tier = map_policy_safety_tier(resolved.rule.safety_tier);
        let idempotency = derive_idempotency(&method.http_method, safety_tier);
        let input_schema = build_input_schema(method, &snapshot.schemas);
        let output_schema = build_output_schema(method, &snapshot.schemas);
        let required_scopes = collect_required_scopes(method, resolved.rule);
        let ai_hints = build_agent_hint(method, resolved.rule, approval_mode, &input_schema);
        let summary = build_operation_summary(method, &snapshot.service.api_name);

        let operation = OperationInfo {
            id: operation_id,
            summary: summary.clone(),
            description: method.description.clone(),
            input_schema: input_schema.clone(),
            output_schema: output_schema.clone(),
            capability: capability.clone(),
            risk_level,
            safety_tier,
            idempotency,
            ai_hints: ai_hints.clone(),
            rate_limit: None,
            requires_approval: approval_mode,
        };

        operations.push(operation.clone());
        mcp_tools.push(build_mcp_tool_descriptor(
            &operation,
            resolved.rule,
            &required_scopes,
        ));
        agent_skills.push(build_agent_skill_artifact(
            &operation,
            method,
            resolved.rule,
            service_policy,
            &required_scopes,
        ));
        manifest_operations.push(build_manifest_operation_fragment(
            &operation,
            resolved.rule,
            &required_scopes,
        ));
    }

    let introspection = Introspection {
        operations,
        events: Vec::<EventInfo>::new(),
        resource_types: Vec::<ResourceTypeInfo>::new(),
        auth_caps: None,
        event_caps: None,
    };

    let manifest_fragment = GoogleManifestFragment {
        connector_id: format!("fcp.google.{}", snapshot.service.api_name),
        operations: manifest_operations,
    };

    Ok(GoogleGeneratedArtifacts {
        service_identity: snapshot.service.identity(),
        introspection,
        mcp_tools,
        agent_skills,
        manifest_fragment,
    })
}

fn build_mcp_tool_descriptor(
    operation: &OperationInfo,
    rule: &GoogleOperationPolicyRule,
    required_scopes: &[String],
) -> GoogleMcpToolDescriptor {
    let ai_hints = if operation.ai_hints.when_to_use.is_empty()
        && operation.ai_hints.common_mistakes.is_empty()
        && operation.ai_hints.examples.is_empty()
        && operation.ai_hints.related.is_empty()
    {
        None
    } else {
        Some(operation.ai_hints.clone())
    };

    GoogleMcpToolDescriptor {
        name: operation.id.as_str().to_string(),
        description: operation
            .description
            .clone()
            .unwrap_or_else(|| operation.summary.clone()),
        input_schema: operation.input_schema.clone(),
        output_schema: operation.output_schema.clone(),
        capability: operation.capability.clone(),
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        approval_mode: operation.requires_approval,
        requires_confirmation: operation.requires_approval.is_some(),
        supports_simulate: true,
        required_scopes: required_scopes.to_vec(),
        policy_notes: rule.notes.clone(),
        ai_hints,
    }
}

fn build_agent_skill_artifact(
    operation: &OperationInfo,
    method: &DiscoveryMethod,
    rule: &GoogleOperationPolicyRule,
    service_policy: &GoogleServicePolicy,
    required_scopes: &[String],
) -> GoogleAgentSkillArtifact {
    let skill_id = format!("skill.{}", operation.id.as_str());
    let display_name = format!(
        "Google {} {}",
        service_policy.service,
        method.key.replace('.', " ")
    );

    let mut notes = service_policy.exceptions.clone();
    notes.extend(rule.notes.clone());

    GoogleAgentSkillArtifact {
        skill_id,
        tool_name: operation.id.as_str().to_string(),
        display_name,
        summary: operation.summary.clone(),
        when_to_use: operation.ai_hints.when_to_use.clone(),
        required_capability: operation.capability.as_str().to_string(),
        risk_level: operation.risk_level,
        approval_mode: operation.requires_approval,
        required_scopes: required_scopes.to_vec(),
        recommended_zones: service_policy.recommended_zones.clone(),
        host_allow: service_policy.host_allow.clone(),
        notes,
    }
}

fn build_manifest_operation_fragment(
    operation: &OperationInfo,
    rule: &GoogleOperationPolicyRule,
    required_scopes: &[String],
) -> GoogleManifestOperationFragment {
    GoogleManifestOperationFragment {
        operation_id: operation.id.as_str().to_string(),
        summary: operation.summary.clone(),
        description: operation.description.clone(),
        input_schema: operation.input_schema.clone(),
        output_schema: operation.output_schema.clone(),
        capability: operation.capability.as_str().to_string(),
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        approval_mode: operation.requires_approval,
        requires_confirmation: operation.requires_approval.is_some(),
        supports_simulate: true,
        required_scopes: required_scopes.to_vec(),
        policy_notes: rule.notes.clone(),
    }
}

fn build_operation_summary(method: &DiscoveryMethod, service_api_name: &str) -> String {
    if let Some(description) = method.description.as_deref()
        && let Some(first_sentence) = first_sentence(description)
    {
        return first_sentence;
    }

    format!(
        "Invoke Google {} operation {}",
        service_api_name, method.key
    )
}

fn first_sentence(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    let first = trimmed
        .split_terminator('.')
        .next()
        .map_or(trimmed, str::trim);
    if first.is_empty() {
        None
    } else {
        Some(first.to_string())
    }
}

fn build_agent_hint(
    method: &DiscoveryMethod,
    rule: &GoogleOperationPolicyRule,
    approval_mode: Option<ApprovalMode>,
    input_schema: &Value,
) -> AgentHint {
    let when_to_use = method.description.as_deref().map_or_else(
        || format!("Use for Google method `{}`.", method.key),
        |description| description.trim().to_string(),
    );

    let mut common_mistakes = Vec::new();
    let required_parameters: Vec<String> = method
        .parameters
        .iter()
        .filter_map(|(name, param)| param.required.then_some(name.clone()))
        .collect();
    if !required_parameters.is_empty() {
        common_mistakes.push(format!(
            "Missing required parameters: {}.",
            required_parameters.join(", ")
        ));
    }

    if let Some(mode) = approval_mode {
        common_mistakes.push(format!(
            "Operation requires {mode:?} approval; do not execute without the required gate."
        ));
    }

    if !rule.required_scopes.is_empty() {
        common_mistakes.push("Token must include required OAuth scopes for this operation.".into());
    }

    let mut examples = Vec::new();
    let example_payload = build_example_payload(input_schema);
    if example_payload != "{}" {
        examples.push(example_payload);
    }

    AgentHint {
        when_to_use,
        common_mistakes,
        examples,
        related: Vec::new(),
    }
}

fn build_example_payload(input_schema: &Value) -> String {
    let Some(properties) = input_schema.get("properties").and_then(Value::as_object) else {
        return "{}".to_string();
    };

    let required_keys: Vec<String> = input_schema
        .get("required")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        });

    let mut example = Map::new();
    for key in required_keys {
        if let Some(schema) = properties.get(&key) {
            example.insert(key, placeholder_for_schema(schema, 0));
        }
    }

    Value::Object(example).to_string()
}

fn placeholder_for_schema(schema: &Value, depth: usize) -> Value {
    if depth > 8 {
        return Value::String("<value>".to_string());
    }

    match schema.get("type").and_then(Value::as_str) {
        Some("string") => {
            if schema.get("format").and_then(Value::as_str) == Some("date-time") {
                Value::String("2026-01-01T00:00:00Z".to_string())
            } else {
                Value::String("<value>".to_string())
            }
        }
        Some("integer" | "number") => Value::Number(serde_json::Number::from(1_u64)),
        Some("boolean") => Value::Bool(false),
        Some("array") => {
            let item = schema.get("items").map_or_else(
                || Value::String("<value>".to_string()),
                |inner| placeholder_for_schema(inner, depth + 1),
            );
            Value::Array(vec![item])
        }
        Some("object") => {
            let mut obj = Map::new();
            if let Some(properties) = schema.get("properties").and_then(Value::as_object)
                && let Some(required) = schema.get("required").and_then(Value::as_array)
            {
                for key in required.iter().filter_map(Value::as_str) {
                    if let Some(inner) = properties.get(key) {
                        obj.insert(key.to_string(), placeholder_for_schema(inner, depth + 1));
                    }
                }
            }
            Value::Object(obj)
        }
        _ => Value::String("<value>".to_string()),
    }
}

fn collect_required_scopes(
    method: &DiscoveryMethod,
    rule: &GoogleOperationPolicyRule,
) -> Vec<String> {
    let mut scopes = BTreeSet::new();
    scopes.extend(method.scopes.iter().cloned());
    scopes.extend(rule.required_scopes.iter().cloned());
    scopes.into_iter().collect()
}

fn derive_idempotency(http_method: &str, safety_tier: SafetyTier) -> IdempotencyClass {
    if matches!(safety_tier, SafetyTier::Dangerous | SafetyTier::Critical) {
        return IdempotencyClass::Strict;
    }

    match http_method {
        "GET" | "HEAD" | "OPTIONS" => IdempotencyClass::Strict,
        "PUT" | "DELETE" => IdempotencyClass::BestEffort,
        _ => IdempotencyClass::None,
    }
}

const fn map_policy_risk_level(level: PolicyRiskLevel) -> RiskLevel {
    match level {
        PolicyRiskLevel::Low => RiskLevel::Low,
        PolicyRiskLevel::Medium => RiskLevel::Medium,
        PolicyRiskLevel::High => RiskLevel::High,
        PolicyRiskLevel::Critical => RiskLevel::Critical,
    }
}

const fn map_policy_safety_tier(tier: PolicySafetyTier) -> SafetyTier {
    match tier {
        PolicySafetyTier::Safe => SafetyTier::Safe,
        PolicySafetyTier::Risky => SafetyTier::Risky,
        PolicySafetyTier::Dangerous => SafetyTier::Dangerous,
        PolicySafetyTier::Critical => SafetyTier::Critical,
        PolicySafetyTier::Forbidden => SafetyTier::Forbidden,
    }
}

const fn map_policy_approval_mode(mode: PolicyApprovalMode) -> Option<ApprovalMode> {
    match mode {
        PolicyApprovalMode::None => None,
        PolicyApprovalMode::Policy => Some(ApprovalMode::Policy),
        PolicyApprovalMode::Interactive => Some(ApprovalMode::Interactive),
        PolicyApprovalMode::ElevationToken => Some(ApprovalMode::ElevationToken),
    }
}

fn build_operation_id_string(service_api_name: &str, method_key: &str) -> String {
    let canonical_service = canonicalize_segment(service_api_name);
    let canonical_key = method_key
        .split('.')
        .map(canonicalize_segment)
        .collect::<Vec<_>>()
        .join(".");
    format!("{canonical_service}.{canonical_key}")
}

fn canonicalize_segment(segment: &str) -> String {
    let mut out = String::new();
    let mut prev_alnum = false;

    for ch in segment.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            out.push(ch);
            prev_alnum = true;
            continue;
        }

        if ch.is_ascii_uppercase() {
            if prev_alnum && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_alnum = true;
            continue;
        }

        if !out.ends_with('_') {
            out.push('_');
        }
        prev_alnum = false;
    }

    let mut normalized = out.trim_matches('_').to_string();
    if normalized.is_empty() {
        normalized = "op".to_string();
    }

    if !normalized
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
    {
        normalized.insert(0, 'x');
    }

    normalized
}

fn build_input_schema(
    method: &DiscoveryMethod,
    schemas: &BTreeMap<String, DiscoverySchema>,
) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    for (name, parameter) in &method.parameters {
        properties.insert(name.clone(), parameter_to_json_schema(parameter));
        if parameter.required {
            required.push(name.clone());
        }
    }

    if let Some(request_ref) = &method.request_ref {
        let body_schema = schema_from_ref_name(request_ref, schemas);
        if body_schema
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|entries| !entries.is_empty())
        {
            required.push("body".to_string());
        }
        properties.insert("body".to_string(), body_schema);
    }

    required.sort_unstable();
    required.dedup();

    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    schema.insert("additionalProperties".to_string(), Value::Bool(false));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert(
            "required".to_string(),
            Value::Array(required.into_iter().map(Value::String).collect()),
        );
    }
    Value::Object(schema)
}

fn build_output_schema(
    method: &DiscoveryMethod,
    schemas: &BTreeMap<String, DiscoverySchema>,
) -> Value {
    if let Some(response_ref) = &method.response_ref {
        return schema_from_ref_name(response_ref, schemas);
    }

    if method.supports_media_download {
        let mut schema = Map::new();
        schema.insert("type".to_string(), Value::String("string".to_string()));
        schema.insert(
            "contentEncoding".to_string(),
            Value::String("base64".to_string()),
        );
        return Value::Object(schema);
    }

    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    Value::Object(schema)
}

fn parameter_to_json_schema(parameter: &DiscoveryParameter) -> Value {
    let base_type = map_discovery_type_name(parameter.type_name.as_deref());
    let mut schema = Map::new();

    if parameter.repeated {
        schema.insert("type".to_string(), Value::String("array".to_string()));
        let mut items = Map::new();
        items.insert("type".to_string(), Value::String(base_type.to_string()));
        if let Some(format) = &parameter.format {
            items.insert("format".to_string(), Value::String(format.clone()));
        }
        schema.insert("items".to_string(), Value::Object(items));
    } else {
        schema.insert("type".to_string(), Value::String(base_type.to_string()));
        if let Some(format) = &parameter.format {
            schema.insert("format".to_string(), Value::String(format.clone()));
        }
    }

    let description = parameter.description.as_ref().map_or_else(
        || {
            parameter
                .location
                .as_ref()
                .map(|location| format!("location: {location}"))
        },
        |description| {
            parameter.location.as_ref().map_or_else(
                || Some(description.clone()),
                |location| Some(format!("{description} (location: {location})")),
            )
        },
    );
    if let Some(description) = description {
        schema.insert("description".to_string(), Value::String(description));
    }

    Value::Object(schema)
}

fn map_discovery_type_name(type_name: Option<&str>) -> &'static str {
    match type_name {
        Some("integer") => "integer",
        Some("number") => "number",
        Some("boolean") => "boolean",
        Some("array") => "array",
        Some("object") => "object",
        _ => "string",
    }
}

fn schema_from_ref_name(ref_name: &str, schemas: &BTreeMap<String, DiscoverySchema>) -> Value {
    let mut visited = BTreeSet::new();
    schema_from_ref_name_inner(ref_name, schemas, &mut visited, 0)
}

fn schema_from_ref_name_inner(
    ref_name: &str,
    schemas: &BTreeMap<String, DiscoverySchema>,
    visited: &mut BTreeSet<String>,
    depth: usize,
) -> Value {
    if depth > MAX_SCHEMA_RENDER_DEPTH || !visited.insert(ref_name.to_string()) {
        return fallback_schema();
    }

    let value = schemas
        .get(ref_name)
        .map_or_else(fallback_schema, |schema| {
            discovery_schema_to_json(schema, schemas, visited, depth + 1)
        });

    visited.remove(ref_name);
    value
}

fn discovery_schema_to_json(
    schema: &DiscoverySchema,
    schemas: &BTreeMap<String, DiscoverySchema>,
    visited: &mut BTreeSet<String>,
    depth: usize,
) -> Value {
    if depth > MAX_SCHEMA_RENDER_DEPTH {
        return fallback_schema();
    }

    if let Some(ref_name) = &schema.ref_name {
        return schema_from_ref_name_inner(ref_name, schemas, visited, depth + 1);
    }

    let mut map = Map::new();
    if let Some(type_name) = &schema.type_name {
        map.insert("type".to_string(), Value::String(type_name.clone()));
    }
    if let Some(format) = &schema.format {
        map.insert("format".to_string(), Value::String(format.clone()));
    }
    if let Some(description) = &schema.description {
        map.insert(
            "description".to_string(),
            Value::String(description.clone()),
        );
    }
    if !schema.enum_values.is_empty() {
        map.insert(
            "enum".to_string(),
            Value::Array(
                schema
                    .enum_values
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if !schema.required.is_empty() {
        map.insert(
            "required".to_string(),
            Value::Array(schema.required.iter().cloned().map(Value::String).collect()),
        );
    }
    if !schema.properties.is_empty() {
        let mut properties = Map::new();
        for (key, property_schema) in &schema.properties {
            properties.insert(
                key.clone(),
                discovery_schema_to_json(property_schema, schemas, visited, depth + 1),
            );
        }
        map.insert("properties".to_string(), Value::Object(properties));
        map.entry("type".to_string())
            .or_insert_with(|| Value::String("object".to_string()));
    }
    if let Some(items) = &schema.items {
        map.insert(
            "items".to_string(),
            discovery_schema_to_json(items, schemas, visited, depth + 1),
        );
        map.entry("type".to_string())
            .or_insert_with(|| Value::String("array".to_string()));
    }
    if let Some(additional) = &schema.additional_properties {
        map.insert(
            "additionalProperties".to_string(),
            discovery_schema_to_json(additional, schemas, visited, depth + 1),
        );
    }

    if map.is_empty() {
        fallback_schema()
    } else {
        Value::Object(map)
    }
}

fn fallback_schema() -> Value {
    let mut map = Map::new();
    map.insert("type".to_string(), Value::String("object".to_string()));
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DiscoveryEndpointKind, DiscoveryServiceId, normalize_snapshot_bytes,
        policy::default_google_policy_catalog,
    };

    const GMAIL_FIXTURE: &str = include_str!("../data/fixtures/gmail_discovery.v1.json");
    const UNKNOWN_SERVICE_FIXTURE: &str = include_str!("../data/fixtures/unknown_service.v1.json");
    const GMAIL_GOLDEN_DIGEST: &str =
        include_str!("../data/golden/gmail_generated_artifacts.v1.blake3");

    #[test]
    fn generation_keeps_introspection_mcp_skills_and_manifest_in_sync() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid service id");
        let normalized = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize fixture");
        let policy = default_google_policy_catalog();

        let generated =
            generate_google_service_artifacts(&normalized.snapshot, &policy).expect("generation");

        assert_eq!(generated.operation_count(), 3);
        assert_eq!(
            generated.introspection.operations.len(),
            generated.mcp_tools.len()
        );
        assert_eq!(
            generated.introspection.operations.len(),
            generated.agent_skills.len()
        );
        assert_eq!(
            generated.introspection.operations.len(),
            generated.manifest_fragment.operations.len()
        );
        assert_eq!(generated.manifest_fragment.connector_id, "fcp.google.gmail");

        let list = generated
            .introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == "gmail.users.messages.list")
            .expect("list operation");
        assert_eq!(list.capability.as_str(), "gmail.read");
        assert!(list.requires_approval.is_none());
        assert!(matches!(list.idempotency, IdempotencyClass::Strict));

        let send = generated
            .introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == "gmail.users.messages.send")
            .expect("send operation");
        assert_eq!(send.capability.as_str(), "gmail.send");
        assert!(matches!(
            send.requires_approval,
            Some(ApprovalMode::Interactive)
        ));
        assert!(matches!(send.idempotency, IdempotencyClass::Strict));

        let send_required = send
            .input_schema
            .get("required")
            .and_then(Value::as_array)
            .expect("required array");
        let required_keys: BTreeSet<&str> =
            send_required.iter().filter_map(Value::as_str).collect();
        assert!(required_keys.contains("body"));
        assert!(required_keys.contains("userId"));

        let send_manifest = generated
            .manifest_fragment
            .operations
            .iter()
            .find(|op| op.operation_id == "gmail.users.messages.send")
            .expect("send operation in manifest fragment");
        assert_eq!(send_manifest.capability, "gmail.send");
        assert!(matches!(
            send_manifest.approval_mode,
            Some(ApprovalMode::Interactive)
        ));
    }

    #[test]
    fn generation_canonicalizes_operation_ids_from_method_keys() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid service id");
        let normalized = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize fixture");
        let policy = default_google_policy_catalog();

        let generated =
            generate_google_service_artifacts(&normalized.snapshot, &policy).expect("generation");
        assert!(
            generated
                .introspection
                .operations
                .iter()
                .any(|op| op.id.as_str() == "gmail.users.messages.list_history")
        );
    }

    #[test]
    fn generation_golden_digest_is_stable() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid service id");
        let normalized = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize fixture");
        let policy = default_google_policy_catalog();

        let generated =
            generate_google_service_artifacts(&normalized.snapshot, &policy).expect("generation");
        let serialized = serde_json::to_vec(&generated).expect("serialize generated artifacts");
        let actual_digest = blake3::hash(&serialized).to_hex().to_string();
        let expected_digest = GMAIL_GOLDEN_DIGEST.trim();

        assert_eq!(
            actual_digest, expected_digest,
            "golden digest drift detected; update {} if this change is intentional",
            "../data/golden/gmail_generated_artifacts.v1.blake3"
        );
    }

    #[test]
    fn generation_fails_when_service_policy_is_missing() {
        let service = DiscoveryServiceId::new("foo", "v1").expect("valid service id");
        let normalized = normalize_snapshot_bytes(
            &service,
            UNKNOWN_SERVICE_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize fixture");
        let policy = default_google_policy_catalog();

        let error = generate_google_service_artifacts(&normalized.snapshot, &policy)
            .expect_err("missing policy");
        assert!(matches!(
            error,
            GoogleGenerationError::MissingServicePolicy { service } if service == "foo"
        ));
    }
}
