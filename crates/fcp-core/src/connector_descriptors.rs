//! Shared connector metadata descriptors for auth, prerequisites, and readiness.
//!
//! These types normalize connector metadata beyond raw operation schemas so
//! host, CLI, onboarding, and access-planning layers can share one source of
//! truth.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AuthCaps, ConnectorHealth, OAuthConfig, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, ReadinessResponse, SelfCheckReport, SelfCheckStatus,
};

/// Normalized status for connector metadata surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorStatus {
    /// The surface is fully ready and verified.
    Ready,
    /// The surface works but has reduced fidelity or warnings.
    Degraded,
    /// The surface is explicitly failing or unavailable.
    Failed,
    /// Required metadata or setup is missing.
    Missing,
    /// Known metadata exists but has drifted from the expected state.
    Drifted,
    /// The surface could not be verified from the current evidence.
    Unverifiable,
    /// Policy currently blocks verification or use.
    PolicyBlocked,
    /// The connector does not implement this surface.
    Unsupported,
    /// No trustworthy signal is available yet.
    Unknown,
}

impl DescriptorStatus {
    #[must_use]
    const fn rank(self) -> u8 {
        match self {
            Self::Ready => 0,
            Self::Unknown => 1,
            Self::Unsupported => 2,
            Self::Unverifiable => 3,
            Self::Degraded => 4,
            Self::Drifted => 5,
            Self::Missing => 6,
            Self::PolicyBlocked => 7,
            Self::Failed => 8,
        }
    }

    /// Combine two statuses, keeping the more severe one.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

impl From<&SelfCheckReport> for DescriptorStatus {
    fn from(report: &SelfCheckReport) -> Self {
        match report.status {
            SelfCheckStatus::Ok => Self::Ready,
            SelfCheckStatus::Degraded => Self::Degraded,
            SelfCheckStatus::Failed => Self::Failed,
            SelfCheckStatus::Unsupported => Self::Unsupported,
        }
    }
}

impl From<&ConnectorHealth> for DescriptorStatus {
    fn from(health: &ConnectorHealth) -> Self {
        match health {
            ConnectorHealth::Healthy => Self::Ready,
            ConnectorHealth::Degraded { .. } => Self::Degraded,
            ConnectorHealth::Unavailable { .. } => Self::Failed,
        }
    }
}

/// A single normalized metadata check or signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorCheck {
    /// Stable check identifier.
    pub id: String,
    /// Normalized status for the check.
    pub status: DescriptorStatus,
    /// Human-readable summary.
    pub summary: String,
    /// Optional structured details or evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    /// Optional remediation hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl DescriptorCheck {
    /// Create a new metadata check.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        status: DescriptorStatus,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status,
            summary: summary.into(),
            details: None,
            remediation: None,
        }
    }

    /// Attach structured details to the check.
    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Attach a remediation hint to the check.
    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

/// Shared connector metadata rollup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorDescriptor {
    /// Canonical connector identifier.
    pub connector_id: String,
    /// Optional human-readable display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Declared connector archetypes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archetypes: Vec<String>,
    /// Supported zones surfaced by the current source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_zones: Vec<String>,
    /// Runtime format label such as `native` or `wasi`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_format: Option<String>,
    /// Optional connector state model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_model: Option<String>,
    /// Operation metadata surfaced for the connector.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<OperationInfo>,
    /// Authentication surface metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthDescriptor>,
    /// Provisioning and prerequisite metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prerequisites: Option<PrerequisiteCatalog>,
    /// Runtime readiness metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness: Option<ReadinessDescriptor>,
}

impl ConnectorDescriptor {
    /// Create a new descriptor for one connector.
    #[must_use]
    pub fn new(connector_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
            display_name: None,
            version: None,
            description: None,
            archetypes: Vec::new(),
            supported_zones: Vec::new(),
            runtime_format: None,
            state_model: None,
            operations: Vec::new(),
            auth: None,
            prerequisites: None,
            readiness: None,
        }
    }

    /// Compute the worst status across auth, prerequisites, and readiness.
    #[must_use]
    pub const fn overall_status(&self) -> DescriptorStatus {
        let mut status = DescriptorStatus::Unknown;
        if let Some(auth) = &self.auth {
            status = status.combine(auth.status);
        }
        if let Some(prerequisites) = &self.prerequisites {
            status = status.combine(prerequisites.status);
        }
        if let Some(readiness) = &self.readiness {
            status = status.combine(readiness.status);
        }
        status
    }
}

/// Shared authentication metadata for a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDescriptor {
    /// Aggregate auth status.
    pub status: DescriptorStatus,
    /// Short operator-facing summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Supported auth methods advertised by the connector.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_methods: Vec<String>,
    /// Optional `OAuth` flow configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthConfig>,
    /// Active auth method when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_method: Option<String>,
    /// Whether the active configuration uses a secret reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses_secret_reference: Option<bool>,
    /// Structured auth checks or evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<DescriptorCheck>,
}

impl AuthDescriptor {
    /// Create an auth descriptor from advertised auth capabilities.
    #[must_use]
    pub fn from_auth_caps(auth_caps: &AuthCaps) -> Self {
        let status = if auth_caps.methods.is_empty() && auth_caps.oauth.is_none() {
            DescriptorStatus::Unknown
        } else {
            DescriptorStatus::Unverifiable
        };

        Self {
            status,
            summary: Some(
                "Connector advertises auth methods, but active auth state has not been verified yet."
                    .to_string(),
            ),
            supported_methods: auth_caps.methods.clone(),
            oauth: auth_caps.oauth.clone(),
            active_method: None,
            uses_secret_reference: None,
            checks: Vec::new(),
        }
    }

    /// Create an auth descriptor whose state is currently unverifiable.
    #[must_use]
    pub fn unverifiable(summary: impl Into<String>) -> Self {
        Self {
            status: DescriptorStatus::Unverifiable,
            summary: Some(summary.into()),
            supported_methods: Vec::new(),
            oauth: None,
            active_method: None,
            uses_secret_reference: None,
            checks: Vec::new(),
        }
    }

    /// Mark the auth descriptor as actively configured.
    #[must_use]
    pub fn configured(
        mut self,
        active_method: impl Into<String>,
        uses_secret_reference: bool,
    ) -> Self {
        self.status = DescriptorStatus::Ready;
        self.active_method = Some(active_method.into());
        self.uses_secret_reference = Some(uses_secret_reference);
        self
    }

    /// Attach a check and fold its status into the aggregate status.
    #[must_use]
    pub fn with_check(mut self, check: DescriptorCheck) -> Self {
        self.status = self.status.combine(check.status);
        self.checks.push(check);
        self
    }
}

/// Stable prerequisite status vocabulary for onboarding and repair flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrerequisiteStatus {
    /// The prerequisite is satisfied.
    Satisfied,
    /// Required setup is missing.
    Missing,
    /// Existing setup is present but drifted.
    Drifted,
    /// The current source cannot verify the prerequisite.
    Unverifiable,
    /// Policy currently blocks satisfying or checking the prerequisite.
    PolicyBlocked,
}

impl From<PrerequisiteStatus> for DescriptorStatus {
    fn from(status: PrerequisiteStatus) -> Self {
        match status {
            PrerequisiteStatus::Satisfied => Self::Ready,
            PrerequisiteStatus::Missing => Self::Missing,
            PrerequisiteStatus::Drifted => Self::Drifted,
            PrerequisiteStatus::Unverifiable => Self::Unverifiable,
            PrerequisiteStatus::PolicyBlocked => Self::PolicyBlocked,
        }
    }
}

/// Normalized prerequisite kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrerequisiteKind {
    /// Non-secret user input is required.
    UserInput,
    /// Secret user input is required.
    SecretInput,
    /// The caller must open a URL or browser flow.
    LaunchUrl,
    /// `OAuth` flow is required.
    Oauth,
    /// Webhook registration or validation is required.
    Webhook,
    /// A prompted secret must be persisted or referenced.
    CredentialPersistence,
}

/// A single prerequisite item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrerequisiteDescriptor {
    /// Stable prerequisite identifier.
    pub id: String,
    /// Normalized prerequisite kind.
    pub kind: PrerequisiteKind,
    /// Current prerequisite status.
    pub status: PrerequisiteStatus,
    /// Short human-readable summary.
    pub summary: String,
    /// Upstream prerequisite dependencies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    /// Whether satisfying this prerequisite requires approval.
    #[serde(default)]
    pub requires_approval: bool,
    /// Optional structured step details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl PrerequisiteDescriptor {
    /// Create a prerequisite item from a provisioning step.
    #[must_use]
    pub fn from_step(step: &ProvisioningStep) -> Self {
        let (kind, summary) = match &step.kind {
            ProvisioningStepType::PromptUser { message } => {
                (PrerequisiteKind::UserInput, message.clone())
            }
            ProvisioningStepType::PromptSecret { message } => {
                (PrerequisiteKind::SecretInput, message.clone())
            }
            ProvisioningStepType::OpenUrl { url } => (
                PrerequisiteKind::LaunchUrl,
                format!("Open {url} to complete connector setup."),
            ),
            ProvisioningStepType::StoreSecret { key, scope, .. } => (
                PrerequisiteKind::CredentialPersistence,
                format!("Persist secret `{key}` in scope `{scope}`."),
            ),
            ProvisioningStepType::Oauth { flow } => (PrerequisiteKind::Oauth, oauth_summary(flow)),
            ProvisioningStepType::Webhook { registration } => (
                PrerequisiteKind::Webhook,
                format!(
                    "Register webhook at {} for {} event(s).",
                    registration.registration_url,
                    registration.events.len()
                ),
            ),
        };

        Self {
            id: step.id.as_str().to_owned(),
            kind,
            status: PrerequisiteStatus::Unverifiable,
            summary,
            depends_on: step
                .depends_on
                .iter()
                .map(|dependency| dependency.as_str().to_owned())
                .collect(),
            requires_approval: step.requires_approval,
            details: serde_json::to_value(&step.kind).ok(),
        }
    }
}

/// A prerequisite catalog derived from provisioning metadata and runtime checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrerequisiteCatalog {
    /// Aggregate prerequisite status.
    pub status: DescriptorStatus,
    /// Short operator-facing summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// The source provisioning recipe when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipe: Option<ProvisioningRecipe>,
    /// Individual prerequisite items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<PrerequisiteDescriptor>,
}

impl PrerequisiteCatalog {
    /// Create a prerequisite catalog from a provisioning recipe.
    #[must_use]
    pub fn from_recipe(recipe: ProvisioningRecipe) -> Self {
        let items = recipe
            .steps
            .iter()
            .map(PrerequisiteDescriptor::from_step)
            .collect::<Vec<_>>();

        let status = if items.is_empty() {
            DescriptorStatus::Ready
        } else {
            DescriptorStatus::Unverifiable
        };

        let summary = if items.is_empty() {
            Some("Connector declares no provisioning prerequisites.".to_string())
        } else {
            Some(
                "Provisioning recipe is available, but prerequisite state has not been verified yet."
                    .to_string(),
            )
        };

        Self {
            status,
            summary,
            recipe: Some(recipe),
            items,
        }
    }

    /// Create a prerequisite catalog whose state is currently unverifiable.
    #[must_use]
    pub fn unverifiable(summary: impl Into<String>) -> Self {
        Self {
            status: DescriptorStatus::Unverifiable,
            summary: Some(summary.into()),
            recipe: None,
            items: Vec::new(),
        }
    }
}

/// Shared readiness metadata for connector bring-up and runtime health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessDescriptor {
    /// Aggregate readiness status.
    pub status: DescriptorStatus,
    /// Short operator-facing summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// External-facing connector health when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<ConnectorHealth>,
    /// Connector self-check report when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_check: Option<SelfCheckReport>,
    /// Structured readiness response when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness: Option<ReadinessResponse>,
    /// Individual checks contributing to readiness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<DescriptorCheck>,
}

impl ReadinessDescriptor {
    /// Create an unverifiable readiness descriptor.
    #[must_use]
    pub fn unverifiable(summary: impl Into<String>) -> Self {
        Self {
            status: DescriptorStatus::Unverifiable,
            summary: Some(summary.into()),
            health: None,
            self_check: None,
            readiness: None,
            checks: Vec::new(),
        }
    }

    /// Create a readiness descriptor from a self-check report.
    #[must_use]
    pub fn from_self_check(report: SelfCheckReport) -> Self {
        let status = DescriptorStatus::from(&report);
        let summary = report.message.clone();
        let checks = report
            .reason_code
            .as_ref()
            .map_or_else(Vec::new, |reason_code| {
                vec![DescriptorCheck::new(
                    reason_code.clone(),
                    status,
                    report
                        .message
                        .clone()
                        .unwrap_or_else(|| reason_code.clone()),
                )]
            });

        Self {
            status,
            summary,
            health: None,
            self_check: Some(report),
            readiness: None,
            checks,
        }
    }

    /// Create a readiness descriptor from a readiness response.
    #[must_use]
    pub fn from_readiness_response(readiness: ReadinessResponse) -> Self {
        let status = if readiness.ready && readiness.components.values().all(|ready| *ready) {
            DescriptorStatus::Ready
        } else {
            DescriptorStatus::Failed
        };

        let mut checks = readiness
            .components
            .iter()
            .map(|(component, ready)| {
                DescriptorCheck::new(
                    component.clone(),
                    if *ready {
                        DescriptorStatus::Ready
                    } else {
                        DescriptorStatus::Failed
                    },
                    if *ready {
                        format!("{component} is ready.")
                    } else {
                        format!("{component} is not ready.")
                    },
                )
            })
            .collect::<Vec<_>>();
        checks.sort_by(|left, right| left.id.cmp(&right.id));

        Self {
            status,
            summary: Some(if readiness.ready {
                "Connector reported ready.".to_string()
            } else {
                "Connector reported one or more readiness failures.".to_string()
            }),
            health: None,
            self_check: None,
            readiness: Some(readiness),
            checks,
        }
    }

    /// Attach connector health and fold it into the aggregate status.
    #[must_use]
    pub fn with_health(mut self, health: ConnectorHealth) -> Self {
        let health_status = DescriptorStatus::from(&health);
        self.status = self.status.combine(health_status);
        if self.summary.is_none() {
            self.summary = Some(match &health {
                ConnectorHealth::Healthy => "Connector reports healthy runtime state.".to_string(),
                ConnectorHealth::Degraded { reason }
                | ConnectorHealth::Unavailable { reason, .. } => reason.clone(),
            });
        }
        self.health = Some(health);
        self
    }

    /// Attach a check and fold it into the aggregate status.
    #[must_use]
    pub fn with_check(mut self, check: DescriptorCheck) -> Self {
        self.status = self.status.combine(check.status);
        self.checks.push(check);
        self
    }
}

fn oauth_summary(flow: &crate::OAuthRecipe) -> String {
    match flow {
        crate::OAuthRecipe::AuthorizationCodePkce {
            authorization_url, ..
        } => {
            format!("Complete authorization-code `OAuth` flow via {authorization_url}.")
        }
        crate::OAuthRecipe::DeviceCode {
            device_authorization_url,
            ..
        } => {
            format!("Complete device-code `OAuth` flow via {device_authorization_url}.")
        }
        crate::OAuthRecipe::ClientCredentials { token_url, .. } => {
            format!("Obtain a client-credentials token from {token_url}.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentHint, ApprovalMode, CapabilityId, IdempotencyClass, OperationId, RecipeId, RiskLevel,
        SafetyTier, StepId,
    };

    fn sample_operation() -> OperationInfo {
        OperationInfo {
            id: OperationId::new("github.list_issues").unwrap(),
            summary: "List issues".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            capability: CapabilityId::new("github.read").unwrap(),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint::default(),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        }
    }

    #[test]
    fn auth_descriptor_from_auth_caps_preserves_methods_and_oauth() {
        let descriptor = AuthDescriptor::from_auth_caps(&AuthCaps {
            methods: vec!["oauth2".to_string(), "credential_id".to_string()],
            oauth: Some(OAuthConfig {
                authorize_url: "https://example.com/auth".to_string(),
                token_url: "https://example.com/token".to_string(),
                scopes: vec!["repo".to_string()],
            }),
        });

        assert_eq!(descriptor.status, DescriptorStatus::Unverifiable);
        assert_eq!(descriptor.supported_methods.len(), 2);
        assert_eq!(
            descriptor.oauth.as_ref().map(|oauth| oauth.scopes.clone()),
            Some(vec!["repo".to_string()])
        );
    }

    #[test]
    fn prerequisite_catalog_from_recipe_maps_steps() {
        let recipe = ProvisioningRecipe::new(
            RecipeId::new("github.onboarding"),
            "1",
            "Bring GitHub online",
        )
        .with_step(ProvisioningStep::new(
            StepId::new("oauth"),
            ProvisioningStepType::Oauth {
                flow: crate::OAuthRecipe::AuthorizationCodePkce {
                    authorization_url: "https://github.com/login/oauth/authorize".to_string(),
                    token_url: "https://github.com/login/oauth/access_token".to_string(),
                    scopes: vec!["repo".to_string()],
                    auto_browser: true,
                    callback_port: 8787,
                },
            },
        ))
        .with_step(
            ProvisioningStep::new(
                StepId::new("webhook"),
                ProvisioningStepType::Webhook {
                    registration: crate::WebhookRecipe {
                        registration_url: "https://api.github.com/hooks".to_string(),
                        events: vec!["push".to_string()],
                        verification: crate::WebhookVerification::HmacSignature {
                            algorithm: "sha256".to_string(),
                            header: "X-Hub-Signature-256".to_string(),
                        },
                        retry_policy: crate::RetryConfig::default(),
                    },
                },
            )
            .depends_on(StepId::new("oauth")),
        );

        let catalog = PrerequisiteCatalog::from_recipe(recipe);

        assert_eq!(catalog.status, DescriptorStatus::Unverifiable);
        assert_eq!(catalog.items.len(), 2);
        assert_eq!(catalog.items[0].kind, PrerequisiteKind::Oauth);
        assert_eq!(catalog.items[1].kind, PrerequisiteKind::Webhook);
        assert_eq!(catalog.items[1].depends_on, vec!["oauth".to_string()]);
    }

    #[test]
    fn readiness_descriptor_from_readiness_response_sorts_component_checks() {
        let mut components = std::collections::HashMap::new();
        components.insert("network".to_string(), false);
        components.insert("config".to_string(), true);

        let descriptor = ReadinessDescriptor::from_readiness_response(ReadinessResponse {
            ready: false,
            components,
            timestamp: chrono::Utc::now(),
        });

        assert_eq!(descriptor.status, DescriptorStatus::Failed);
        assert_eq!(descriptor.checks[0].id, "config");
        assert_eq!(descriptor.checks[0].status, DescriptorStatus::Ready);
        assert_eq!(descriptor.checks[1].id, "network");
        assert_eq!(descriptor.checks[1].status, DescriptorStatus::Failed);
    }

    #[test]
    fn connector_descriptor_overall_status_uses_worst_surface() {
        let mut descriptor = ConnectorDescriptor::new("github");
        descriptor.operations.push(sample_operation());
        descriptor.auth = Some(
            AuthDescriptor::unverifiable("auth state not yet checked")
                .configured("credential_id", true)
                .with_check(DescriptorCheck::new(
                    "credential_ref",
                    DescriptorStatus::Ready,
                    "Using secret reference.",
                )),
        );
        descriptor.prerequisites = Some(PrerequisiteCatalog::unverifiable(
            "service-side prerequisites not checked",
        ));
        descriptor.readiness = Some(
            ReadinessDescriptor::from_self_check(SelfCheckReport::failed(
                "network_down",
                "connector cannot reach upstream",
            ))
            .with_health(ConnectorHealth::degraded("retry budget nearly exhausted")),
        );

        assert_eq!(descriptor.overall_status(), DescriptorStatus::Failed);
    }
}
