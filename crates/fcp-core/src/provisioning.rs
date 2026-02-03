//! Automation recipes and provisioning interface (NORMATIVE).
//!
//! Implements the recipe model and provisioning workflow described in
//! `FCP_Specification_V2.md` §12. This is the standard connector-facing
//! interface for automated setup (OAuth, webhooks, secret capture) with
//! minimal human prompts and deterministic, idempotent steps.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{FcpError, RetryConfig};

/// Unique identifier for a provisioning recipe (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecipeId(String);

impl RecipeId {
    /// Create a new recipe ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the recipe ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecipeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for RecipeId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for RecipeId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Unique identifier for a provisioning step (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StepId(String);

impl StepId {
    /// Create a new step ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the step ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StepId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for StepId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for StepId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Provisioning recipe definition (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningRecipe {
    /// Unique recipe identifier.
    pub id: RecipeId,
    /// Recipe version (opaque string, e.g., "1").
    pub version: String,
    /// Human-readable description.
    pub description: String,
    /// Ordered steps for the recipe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<ProvisioningStep>,
}

impl ProvisioningRecipe {
    /// Create a new recipe.
    #[must_use]
    pub fn new(id: RecipeId, version: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id,
            version: version.into(),
            description: description.into(),
            steps: Vec::new(),
        }
    }

    /// Add a step to the recipe.
    #[must_use]
    pub fn with_step(mut self, step: ProvisioningStep) -> Self {
        self.steps.push(step);
        self
    }
}

/// A single provisioning step (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningStep {
    /// Step identifier.
    pub id: StepId,
    /// Step type and parameters.
    #[serde(flatten)]
    pub kind: ProvisioningStepType,
    /// Dependencies on other steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<StepId>,
    /// Whether this step requires explicit approval.
    #[serde(default)]
    pub requires_approval: bool,
}

impl ProvisioningStep {
    /// Create a new provisioning step.
    #[must_use]
    pub const fn new(id: StepId, kind: ProvisioningStepType) -> Self {
        Self {
            id,
            kind,
            depends_on: Vec::new(),
            requires_approval: false,
        }
    }

    /// Mark this step as requiring approval.
    #[must_use]
    pub const fn with_approval(mut self) -> Self {
        self.requires_approval = true;
        self
    }

    /// Add a dependency.
    #[must_use]
    pub fn depends_on(mut self, step: StepId) -> Self {
        self.depends_on.push(step);
        self
    }
}

/// Step types for provisioning (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProvisioningStepType {
    /// Prompt the user for a non-secret value.
    PromptUser {
        /// Prompt message shown to the user.
        message: String,
    },
    /// Prompt the user for a secret value (e.g., API token).
    PromptSecret {
        /// Prompt message shown to the user.
        message: String,
    },
    /// Open a URL for user interaction (OAuth consent, `BotFather`, etc.).
    OpenUrl {
        /// URL to open.
        url: String,
    },
    /// Store a secret from a previous prompt.
    StoreSecret {
        /// Logical key name for the stored secret.
        key: String,
        /// Identifier of the step that provided the value.
        value_from: StepId,
        /// Scope for the stored secret (e.g., "connector:fcp.telegram").
        scope: String,
    },
    /// OAuth provisioning step.
    Oauth {
        /// OAuth flow definition.
        flow: OAuthRecipe,
    },
    /// Webhook registration step.
    Webhook {
        /// Webhook registration definition.
        registration: WebhookRecipe,
    },
}

/// OAuth flow definition for provisioning (NORMATIVE when used).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OAuthRecipe {
    /// Authorization Code with PKCE (interactive, browser-based).
    AuthorizationCodePkce {
        /// Authorization URL.
        authorization_url: String,
        /// Token URL.
        token_url: String,
        /// Scopes requested.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
        /// Whether to auto-open the browser.
        #[serde(default)]
        auto_browser: bool,
        /// Callback port for the local server.
        callback_port: u16,
    },
    /// Device Authorization Grant (headless/CLI).
    DeviceCode {
        /// Device authorization URL.
        device_authorization_url: String,
        /// Token URL.
        token_url: String,
        /// Scopes requested.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
        /// Poll interval (seconds).
        poll_interval_seconds: u64,
    },
    /// Client credentials (machine-to-machine).
    ClientCredentials {
        /// Token URL.
        token_url: String,
        /// Scopes requested.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
    },
}

/// Webhook registration definition (NORMATIVE when used).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRecipe {
    /// Registration endpoint for the upstream service.
    pub registration_url: String,
    /// Events to subscribe to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<String>,
    /// Verification method for inbound webhook requests.
    pub verification: WebhookVerification,
    /// Retry policy for registration.
    #[serde(default)]
    pub retry_policy: RetryConfig,
}

/// Webhook verification strategies (NORMATIVE when used).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebhookVerification {
    /// HMAC signature verification.
    HmacSignature {
        /// Algorithm name (e.g., "sha256").
        algorithm: String,
        /// Header containing the signature.
        header: String,
    },
    /// Challenge-response verification.
    ChallengeResponse {
        /// Query parameter containing the challenge.
        challenge_param: String,
    },
    /// Ed25519 signature verification.
    Ed25519Signature {
        /// Header containing the public key or key ID.
        public_key_header: String,
    },
}

/// Status of an active provisioning flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningStatus {
    /// Provisioning has not started.
    NotStarted,
    /// Provisioning is in progress.
    InProgress,
    /// Waiting for user interaction.
    AwaitingUser,
    /// Provisioning completed successfully.
    Completed,
    /// Provisioning failed.
    Failed,
    /// Provisioning was aborted.
    Aborted,
}

/// Current provisioning state (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningState {
    /// Current status.
    pub status: ProvisioningStatus,
    /// Current step being executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_step: Option<StepId>,
    /// Completed steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed_steps: Vec<StepId>,
    /// Remaining steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining_steps: Vec<StepId>,
    /// Human prompts awaiting completion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub awaiting_human: Vec<HumanPrompt>,
    /// Optional error message for failed status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl ProvisioningState {
    /// Create a new state in `NotStarted`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            status: ProvisioningStatus::NotStarted,
            current_step: None,
            completed_steps: Vec::new(),
            remaining_steps: Vec::new(),
            awaiting_human: Vec::new(),
            error_message: None,
        }
    }
}

impl Default for ProvisioningState {
    fn default() -> Self {
        Self::new()
    }
}

/// Progress summary for provisioning (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningProgress {
    /// Current step being executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_step: Option<StepId>,
    /// Completed steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed: Vec<StepId>,
    /// Remaining steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<StepId>,
    /// Human prompts awaiting completion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub awaiting_human: Vec<HumanPrompt>,
}

/// Human prompt definition for provisioning (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanPrompt {
    /// Associated step ID.
    pub step_id: StepId,
    /// Prompt type.
    pub prompt_type: HumanPromptType,
    /// Prompt message.
    pub message: String,
    /// Optional URL associated with the prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Prompt types for human interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanPromptType {
    /// Plain text input.
    Text,
    /// Secret input (masked).
    Secret,
    /// Approval/confirmation.
    Approval,
    /// Open a URL.
    Url,
}

/// Setup descriptor for agent-visible provisioning (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupDescriptor {
    /// MCP-compatible tool descriptor (JSON form).
    pub tool_descriptor: serde_json::Value,
    /// Required human interactions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub human_prompts: Vec<HumanPrompt>,
    /// Estimated duration in milliseconds (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_duration_ms: Option<u64>,
}

/// Result of executing a provisioning step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProvisioningStepResult {
    /// Step completed successfully.
    Completed {
        /// Step identifier.
        step_id: StepId,
    },
    /// Step requires human input.
    AwaitingHuman {
        /// Prompt describing required input.
        prompt: HumanPrompt,
    },
    /// Step is still in progress.
    InProgress {
        /// Step identifier.
        step_id: StepId,
    },
}

/// Result of validating provisioning state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningValidation {
    /// Whether provisioning is valid.
    pub valid: bool,
    /// Validation errors (if any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl ProvisioningValidation {
    /// Create a successful validation.
    #[must_use]
    pub const fn ok() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    /// Create a failed validation.
    #[must_use]
    pub const fn failed(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            errors,
        }
    }
}

/// Provisioning interface for connectors (NORMATIVE).
#[async_trait]
pub trait ProvisioningInterface: Send + Sync {
    /// Describe the setup steps and required human prompts.
    fn describe_setup(&self) -> SetupDescriptor;

    /// Get current provisioning state.
    fn get_state(&self) -> ProvisioningState;

    /// Execute a provisioning step by ID.
    async fn execute_step(&mut self, step_id: StepId) -> Result<ProvisioningStepResult, FcpError>;

    /// Validate provisioning completion.
    fn validate(&self) -> ProvisioningValidation;
}

/// Provisioning operation identifiers (NORMATIVE).
pub mod operations {
    /// Begin auth flow.
    pub const START: &str = "fcp.provision.start";
    /// Check status.
    pub const POLL: &str = "fcp.provision.poll";
    /// Finalize credentials.
    pub const COMPLETE: &str = "fcp.provision.complete";
    /// Cancel and cleanup.
    pub const ABORT: &str = "fcp.provision.abort";
}

#[cfg(test)]
mod tests {
    use super::{ProvisioningRecipe, ProvisioningStep, ProvisioningStepType, RecipeId, StepId};

    #[test]
    fn recipe_serializes_step_type() {
        let step = ProvisioningStep::new(
            StepId::new("bot_token"),
            ProvisioningStepType::PromptSecret {
                message: "Paste token".to_string(),
            },
        );
        let recipe =
            ProvisioningRecipe::new(RecipeId::new("telegram/setup"), "1", "Set up Telegram bot")
                .with_step(step);

        let value = serde_json::to_value(&recipe).expect("serialize recipe");
        let step_val = &value["steps"][0];
        assert_eq!(step_val["type"], "prompt_secret");
        assert_eq!(step_val["id"], "bot_token");
    }
}
