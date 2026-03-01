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
    use super::*;
    use serde_json::json;

    // ─────────────────────────────────────────────────────────────────────────
    // RecipeId
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn recipe_id_new_and_as_str() {
        let id = RecipeId::new("telegram/setup");
        assert_eq!(id.as_str(), "telegram/setup");
    }

    #[test]
    fn recipe_id_display() {
        let id = RecipeId::new("discord/oauth");
        assert_eq!(format!("{id}"), "discord/oauth");
    }

    #[test]
    fn recipe_id_from_string() {
        let id: RecipeId = String::from("openai/setup").into();
        assert_eq!(id.as_str(), "openai/setup");
    }

    #[test]
    fn recipe_id_from_str() {
        let id: RecipeId = "slack/bot".into();
        assert_eq!(id.as_str(), "slack/bot");
    }

    #[test]
    fn recipe_id_serde_roundtrip() {
        let id = RecipeId::new("test/recipe");
        let json = serde_json::to_string(&id).unwrap();
        let decoded: RecipeId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn recipe_id_serde_transparent() {
        let id = RecipeId::new("simple");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"simple\"");
    }

    #[test]
    fn recipe_id_equality() {
        let a = RecipeId::new("same");
        let b = RecipeId::new("same");
        let c = RecipeId::new("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn recipe_id_clone() {
        let a = RecipeId::new("original");
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StepId
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn step_id_new_and_as_str() {
        let id = StepId::new("enter_token");
        assert_eq!(id.as_str(), "enter_token");
    }

    #[test]
    fn step_id_display() {
        let id = StepId::new("oauth_callback");
        assert_eq!(format!("{id}"), "oauth_callback");
    }

    #[test]
    fn step_id_from_string() {
        let id: StepId = String::from("store_key").into();
        assert_eq!(id.as_str(), "store_key");
    }

    #[test]
    fn step_id_from_str() {
        let id: StepId = "prompt_user".into();
        assert_eq!(id.as_str(), "prompt_user");
    }

    #[test]
    fn step_id_serde_roundtrip() {
        let id = StepId::new("test_step");
        let json = serde_json::to_string(&id).unwrap();
        let decoded: StepId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn step_id_serde_transparent() {
        let id = StepId::new("my_step");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"my_step\"");
    }

    #[test]
    fn step_id_hash_key() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(StepId::new("a"));
        set.insert(StepId::new("b"));
        set.insert(StepId::new("a"));
        assert_eq!(set.len(), 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningRecipe
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn recipe_new_has_empty_steps() {
        let recipe = ProvisioningRecipe::new(RecipeId::new("test"), "1", "Test recipe");
        assert!(recipe.steps.is_empty());
        assert_eq!(recipe.id.as_str(), "test");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.description, "Test recipe");
    }

    #[test]
    fn recipe_with_step_chains() {
        let recipe = ProvisioningRecipe::new(RecipeId::new("multi"), "2", "Multi-step")
            .with_step(ProvisioningStep::new(
                StepId::new("s1"),
                ProvisioningStepType::PromptUser {
                    message: "Name?".to_string(),
                },
            ))
            .with_step(ProvisioningStep::new(
                StepId::new("s2"),
                ProvisioningStepType::PromptSecret {
                    message: "Token?".to_string(),
                },
            ));
        assert_eq!(recipe.steps.len(), 2);
        assert_eq!(recipe.steps[0].id.as_str(), "s1");
        assert_eq!(recipe.steps[1].id.as_str(), "s2");
    }

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

    #[test]
    fn recipe_serde_roundtrip() {
        let recipe = ProvisioningRecipe::new(RecipeId::new("test/rt"), "3", "Roundtrip").with_step(
            ProvisioningStep::new(
                StepId::new("step1"),
                ProvisioningStepType::PromptUser {
                    message: "Hello".to_string(),
                },
            ),
        );
        let json = serde_json::to_string(&recipe).unwrap();
        let decoded: ProvisioningRecipe = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, recipe.id);
        assert_eq!(decoded.version, recipe.version);
        assert_eq!(decoded.steps.len(), 1);
    }

    #[test]
    fn recipe_empty_steps_omitted_in_json() {
        let recipe = ProvisioningRecipe::new(RecipeId::new("empty"), "1", "No steps");
        let value = serde_json::to_value(&recipe).unwrap();
        assert!(value.get("steps").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningStep
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn step_new_defaults() {
        let step = ProvisioningStep::new(
            StepId::new("s1"),
            ProvisioningStepType::PromptUser {
                message: "Hi".to_string(),
            },
        );
        assert!(!step.requires_approval);
        assert!(step.depends_on.is_empty());
    }

    #[test]
    fn step_with_approval() {
        let step = ProvisioningStep::new(
            StepId::new("s1"),
            ProvisioningStepType::PromptUser {
                message: "Hi".to_string(),
            },
        )
        .with_approval();
        assert!(step.requires_approval);
    }

    #[test]
    fn step_depends_on_chaining() {
        let step = ProvisioningStep::new(
            StepId::new("s3"),
            ProvisioningStepType::PromptUser {
                message: "Final".to_string(),
            },
        )
        .depends_on(StepId::new("s1"))
        .depends_on(StepId::new("s2"));
        assert_eq!(step.depends_on.len(), 2);
        assert_eq!(step.depends_on[0].as_str(), "s1");
        assert_eq!(step.depends_on[1].as_str(), "s2");
    }

    #[test]
    fn step_empty_depends_on_omitted() {
        let step = ProvisioningStep::new(
            StepId::new("s1"),
            ProvisioningStepType::PromptUser {
                message: "Hi".to_string(),
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        assert!(value.get("depends_on").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningStepType variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn step_type_prompt_user_serde() {
        let step = ProvisioningStep::new(
            StepId::new("name"),
            ProvisioningStepType::PromptUser {
                message: "Enter your name".to_string(),
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        assert_eq!(value["type"], "prompt_user");
        assert_eq!(value["message"], "Enter your name");

        let decoded: ProvisioningStep = serde_json::from_value(value).unwrap();
        assert!(matches!(
            decoded.kind,
            ProvisioningStepType::PromptUser { .. }
        ));
    }

    #[test]
    fn step_type_prompt_secret_serde() {
        let step = ProvisioningStep::new(
            StepId::new("token"),
            ProvisioningStepType::PromptSecret {
                message: "API key".to_string(),
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        assert_eq!(value["type"], "prompt_secret");
    }

    #[test]
    fn step_type_open_url_serde() {
        let step = ProvisioningStep::new(
            StepId::new("consent"),
            ProvisioningStepType::OpenUrl {
                url: "https://example.com/oauth".to_string(),
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        assert_eq!(value["type"], "open_url");
        assert_eq!(value["url"], "https://example.com/oauth");
    }

    #[test]
    fn step_type_store_secret_serde() {
        let step = ProvisioningStep::new(
            StepId::new("store"),
            ProvisioningStepType::StoreSecret {
                key: "api_token".to_string(),
                value_from: StepId::new("prompt_token"),
                scope: "connector:fcp.telegram".to_string(),
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        assert_eq!(value["type"], "store_secret");
        assert_eq!(value["key"], "api_token");
        assert_eq!(value["value_from"], "prompt_token");
        assert_eq!(value["scope"], "connector:fcp.telegram");
    }

    #[test]
    fn step_type_oauth_pkce_serde() {
        let step = ProvisioningStep::new(
            StepId::new("oauth"),
            ProvisioningStepType::Oauth {
                flow: OAuthRecipe::AuthorizationCodePkce {
                    authorization_url: "https://auth.example.com/authorize".to_string(),
                    token_url: "https://auth.example.com/token".to_string(),
                    scopes: vec!["read".to_string(), "write".to_string()],
                    auto_browser: true,
                    callback_port: 8080,
                },
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        assert_eq!(value["type"], "oauth");
        let flow = &value["flow"];
        assert_eq!(flow["type"], "authorization_code_pkce");
        assert_eq!(flow["callback_port"], 8080);
        assert!(flow["auto_browser"].as_bool().unwrap());

        let decoded: ProvisioningStep = serde_json::from_value(value).unwrap();
        assert!(matches!(decoded.kind, ProvisioningStepType::Oauth { .. }));
    }

    #[test]
    fn step_type_oauth_device_code_serde() {
        let step = ProvisioningStep::new(
            StepId::new("device"),
            ProvisioningStepType::Oauth {
                flow: OAuthRecipe::DeviceCode {
                    device_authorization_url: "https://auth.example.com/device".to_string(),
                    token_url: "https://auth.example.com/token".to_string(),
                    scopes: vec!["openid".to_string()],
                    poll_interval_seconds: 5,
                },
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        let flow = &value["flow"];
        assert_eq!(flow["type"], "device_code");
        assert_eq!(flow["poll_interval_seconds"], 5);
    }

    #[test]
    fn step_type_oauth_client_credentials_serde() {
        let step = ProvisioningStep::new(
            StepId::new("m2m"),
            ProvisioningStepType::Oauth {
                flow: OAuthRecipe::ClientCredentials {
                    token_url: "https://auth.example.com/token".to_string(),
                    scopes: Vec::new(),
                },
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        let flow = &value["flow"];
        assert_eq!(flow["type"], "client_credentials");
    }

    #[test]
    fn step_type_webhook_hmac_serde() {
        let step = ProvisioningStep::new(
            StepId::new("webhook"),
            ProvisioningStepType::Webhook {
                registration: WebhookRecipe {
                    registration_url: "https://api.example.com/webhooks".to_string(),
                    events: vec!["push".to_string(), "pull_request".to_string()],
                    verification: WebhookVerification::HmacSignature {
                        algorithm: "sha256".to_string(),
                        header: "X-Hub-Signature-256".to_string(),
                    },
                    retry_policy: RetryConfig::default(),
                },
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        assert_eq!(value["type"], "webhook");
        let reg = &value["registration"];
        assert_eq!(reg["events"].as_array().unwrap().len(), 2);
        let ver = &reg["verification"];
        assert_eq!(ver["type"], "hmac_signature");
        assert_eq!(ver["algorithm"], "sha256");
    }

    #[test]
    fn step_type_webhook_challenge_response_serde() {
        let recipe = WebhookRecipe {
            registration_url: "https://api.example.com/webhooks".to_string(),
            events: Vec::new(),
            verification: WebhookVerification::ChallengeResponse {
                challenge_param: "hub.challenge".to_string(),
            },
            retry_policy: RetryConfig::default(),
        };
        let value = serde_json::to_value(&recipe).unwrap();
        assert_eq!(value["verification"]["type"], "challenge_response");
        assert_eq!(value["verification"]["challenge_param"], "hub.challenge");
    }

    #[test]
    fn step_type_webhook_ed25519_serde() {
        let recipe = WebhookRecipe {
            registration_url: "https://api.example.com/webhooks".to_string(),
            events: vec!["message.create".to_string()],
            verification: WebhookVerification::Ed25519Signature {
                public_key_header: "X-Signature-Ed25519".to_string(),
            },
            retry_policy: RetryConfig::default(),
        };
        let value = serde_json::to_value(&recipe).unwrap();
        assert_eq!(value["verification"]["type"], "ed25519_signature");
        assert_eq!(
            value["verification"]["public_key_header"],
            "X-Signature-Ed25519"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningStatus
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provisioning_status_serde_all_variants() {
        let variants = [
            (ProvisioningStatus::NotStarted, "\"not_started\""),
            (ProvisioningStatus::InProgress, "\"in_progress\""),
            (ProvisioningStatus::AwaitingUser, "\"awaiting_user\""),
            (ProvisioningStatus::Completed, "\"completed\""),
            (ProvisioningStatus::Failed, "\"failed\""),
            (ProvisioningStatus::Aborted, "\"aborted\""),
        ];
        for (status, expected_json) in &variants {
            let json = serde_json::to_string(status).unwrap();
            assert_eq!(
                &json, expected_json,
                "serialization mismatch for {status:?}"
            );
            let decoded: ProvisioningStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, decoded);
        }
    }

    #[test]
    fn provisioning_status_copy() {
        let a = ProvisioningStatus::InProgress;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningState
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provisioning_state_new() {
        let state = ProvisioningState::new();
        assert_eq!(state.status, ProvisioningStatus::NotStarted);
        assert!(state.current_step.is_none());
        assert!(state.completed_steps.is_empty());
        assert!(state.remaining_steps.is_empty());
        assert!(state.awaiting_human.is_empty());
        assert!(state.error_message.is_none());
    }

    #[test]
    fn provisioning_state_default_matches_new() {
        let a = ProvisioningState::new();
        let b = ProvisioningState::default();
        assert_eq!(a.status, b.status);
        assert_eq!(a.current_step.is_none(), b.current_step.is_none());
    }

    #[test]
    fn provisioning_state_serde_minimal() {
        let state = ProvisioningState::new();
        let value = serde_json::to_value(&state).unwrap();
        assert_eq!(value["status"], "not_started");
        // Optional/empty fields should be omitted
        assert!(value.get("current_step").is_none());
        assert!(value.get("error_message").is_none());
    }

    #[test]
    fn provisioning_state_serde_full() {
        let state = ProvisioningState {
            status: ProvisioningStatus::AwaitingUser,
            current_step: Some(StepId::new("oauth_consent")),
            completed_steps: vec![StepId::new("step1")],
            remaining_steps: vec![StepId::new("step3")],
            awaiting_human: vec![HumanPrompt {
                step_id: StepId::new("oauth_consent"),
                prompt_type: HumanPromptType::Url,
                message: "Visit OAuth page".to_string(),
                url: Some("https://example.com/auth".to_string()),
            }],
            error_message: None,
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: ProvisioningState = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, ProvisioningStatus::AwaitingUser);
        assert_eq!(decoded.current_step.unwrap().as_str(), "oauth_consent");
        assert_eq!(decoded.completed_steps.len(), 1);
        assert_eq!(decoded.remaining_steps.len(), 1);
        assert_eq!(decoded.awaiting_human.len(), 1);
    }

    #[test]
    fn provisioning_state_with_error() {
        let state = ProvisioningState {
            status: ProvisioningStatus::Failed,
            current_step: None,
            completed_steps: Vec::new(),
            remaining_steps: Vec::new(),
            awaiting_human: Vec::new(),
            error_message: Some("connection timed out".to_string()),
        };
        let value = serde_json::to_value(&state).unwrap();
        assert_eq!(value["error_message"], "connection timed out");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningProgress
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provisioning_progress_serde() {
        let progress = ProvisioningProgress {
            current_step: Some(StepId::new("s2")),
            completed: vec![StepId::new("s1")],
            remaining: vec![StepId::new("s3"), StepId::new("s4")],
            awaiting_human: Vec::new(),
        };
        let json = serde_json::to_string(&progress).unwrap();
        let decoded: ProvisioningProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.current_step.unwrap().as_str(), "s2");
        assert_eq!(decoded.completed.len(), 1);
        assert_eq!(decoded.remaining.len(), 2);
    }

    #[test]
    fn provisioning_progress_empty_omits_fields() {
        let progress = ProvisioningProgress {
            current_step: None,
            completed: Vec::new(),
            remaining: Vec::new(),
            awaiting_human: Vec::new(),
        };
        let value = serde_json::to_value(&progress).unwrap();
        assert!(value.get("current_step").is_none());
        assert!(value.get("completed").is_none());
        assert!(value.get("remaining").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HumanPrompt + HumanPromptType
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn human_prompt_type_serde_all_variants() {
        let variants = [
            (HumanPromptType::Text, "\"text\""),
            (HumanPromptType::Secret, "\"secret\""),
            (HumanPromptType::Approval, "\"approval\""),
            (HumanPromptType::Url, "\"url\""),
        ];
        for (pt, expected) in &variants {
            let json = serde_json::to_string(pt).unwrap();
            assert_eq!(&json, expected);
            let decoded: HumanPromptType = serde_json::from_str(&json).unwrap();
            assert_eq!(*pt, decoded);
        }
    }

    #[test]
    fn human_prompt_serde_with_url() {
        let prompt = HumanPrompt {
            step_id: StepId::new("oauth"),
            prompt_type: HumanPromptType::Url,
            message: "Visit link".to_string(),
            url: Some("https://example.com".to_string()),
        };
        let json = serde_json::to_string(&prompt).unwrap();
        let decoded: HumanPrompt = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn human_prompt_serde_without_url() {
        let prompt = HumanPrompt {
            step_id: StepId::new("approve"),
            prompt_type: HumanPromptType::Approval,
            message: "Confirm install?".to_string(),
            url: None,
        };
        let value = serde_json::to_value(&prompt).unwrap();
        assert!(value.get("url").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SetupDescriptor
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn setup_descriptor_serde() {
        let desc = SetupDescriptor {
            tool_descriptor: json!({
                "name": "fcp.telegram.setup",
                "description": "Set up Telegram bot connector"
            }),
            human_prompts: vec![HumanPrompt {
                step_id: StepId::new("token"),
                prompt_type: HumanPromptType::Secret,
                message: "Paste bot token".to_string(),
                url: None,
            }],
            estimated_duration_ms: Some(30_000),
        };
        let json = serde_json::to_string(&desc).unwrap();
        let decoded: SetupDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.human_prompts.len(), 1);
        assert_eq!(decoded.estimated_duration_ms, Some(30_000));
    }

    #[test]
    fn setup_descriptor_empty_prompts_omitted() {
        let desc = SetupDescriptor {
            tool_descriptor: json!({}),
            human_prompts: Vec::new(),
            estimated_duration_ms: None,
        };
        let value = serde_json::to_value(&desc).unwrap();
        assert!(value.get("human_prompts").is_none());
        assert!(value.get("estimated_duration_ms").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningStepResult
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn step_result_completed_serde() {
        let result = ProvisioningStepResult::Completed {
            step_id: StepId::new("done"),
        };
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["status"], "completed");
        assert_eq!(value["step_id"], "done");

        let decoded: ProvisioningStepResult = serde_json::from_value(value).unwrap();
        assert!(matches!(decoded, ProvisioningStepResult::Completed { .. }));
    }

    #[test]
    fn step_result_awaiting_human_serde() {
        let result = ProvisioningStepResult::AwaitingHuman {
            prompt: HumanPrompt {
                step_id: StepId::new("consent"),
                prompt_type: HumanPromptType::Approval,
                message: "Allow access?".to_string(),
                url: None,
            },
        };
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["status"], "awaiting_human");
        assert_eq!(value["prompt"]["message"], "Allow access?");
    }

    #[test]
    fn step_result_in_progress_serde() {
        let result = ProvisioningStepResult::InProgress {
            step_id: StepId::new("polling"),
        };
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["status"], "in_progress");
        assert_eq!(value["step_id"], "polling");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningValidation
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validation_ok() {
        let v = ProvisioningValidation::ok();
        assert!(v.valid);
        assert!(v.errors.is_empty());
    }

    #[test]
    fn validation_failed() {
        let v = ProvisioningValidation::failed(vec![
            "missing token".to_string(),
            "invalid scope".to_string(),
        ]);
        assert!(!v.valid);
        assert_eq!(v.errors.len(), 2);
        assert_eq!(v.errors[0], "missing token");
    }

    #[test]
    fn validation_serde_ok() {
        let v = ProvisioningValidation::ok();
        let value = serde_json::to_value(&v).unwrap();
        assert!(value["valid"].as_bool().unwrap());
        // empty errors omitted
        assert!(value.get("errors").is_none());
    }

    #[test]
    fn validation_serde_failed() {
        let v = ProvisioningValidation::failed(vec!["bad".to_string()]);
        let json = serde_json::to_string(&v).unwrap();
        let decoded: ProvisioningValidation = serde_json::from_str(&json).unwrap();
        assert!(!decoded.valid);
        assert_eq!(decoded.errors.len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Operations constants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operations_constants_are_namespaced() {
        assert!(operations::START.starts_with("fcp.provision."));
        assert!(operations::POLL.starts_with("fcp.provision."));
        assert!(operations::COMPLETE.starts_with("fcp.provision."));
        assert!(operations::ABORT.starts_with("fcp.provision."));
    }

    #[test]
    fn operations_constants_unique() {
        let ops = [
            operations::START,
            operations::POLL,
            operations::COMPLETE,
            operations::ABORT,
        ];
        let set: std::collections::HashSet<&str> = ops.iter().copied().collect();
        assert_eq!(set.len(), ops.len());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OAuth recipe variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn oauth_pkce_empty_scopes_omitted() {
        let flow = OAuthRecipe::AuthorizationCodePkce {
            authorization_url: "https://auth.example.com/authorize".to_string(),
            token_url: "https://auth.example.com/token".to_string(),
            scopes: Vec::new(),
            auto_browser: false,
            callback_port: 9090,
        };
        let value = serde_json::to_value(&flow).unwrap();
        assert!(value.get("scopes").is_none());
    }

    #[test]
    fn oauth_device_code_roundtrip() {
        let flow = OAuthRecipe::DeviceCode {
            device_authorization_url: "https://auth.example.com/device".to_string(),
            token_url: "https://auth.example.com/token".to_string(),
            scopes: vec!["profile".to_string()],
            poll_interval_seconds: 10,
        };
        let json = serde_json::to_string(&flow).unwrap();
        let decoded: OAuthRecipe = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            OAuthRecipe::DeviceCode {
                poll_interval_seconds: 10,
                ..
            }
        ));
    }

    #[test]
    fn oauth_client_credentials_roundtrip() {
        let flow = OAuthRecipe::ClientCredentials {
            token_url: "https://auth.example.com/token".to_string(),
            scopes: vec!["api".to_string()],
        };
        let json = serde_json::to_string(&flow).unwrap();
        let decoded: OAuthRecipe = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, OAuthRecipe::ClientCredentials { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WebhookRecipe
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn webhook_recipe_empty_events_omitted() {
        let recipe = WebhookRecipe {
            registration_url: "https://api.example.com/webhooks".to_string(),
            events: Vec::new(),
            verification: WebhookVerification::ChallengeResponse {
                challenge_param: "challenge".to_string(),
            },
            retry_policy: RetryConfig::default(),
        };
        let value = serde_json::to_value(&recipe).unwrap();
        assert!(value.get("events").is_none());
    }

    #[test]
    fn webhook_recipe_serde_roundtrip() {
        let recipe = WebhookRecipe {
            registration_url: "https://api.example.com/webhooks".to_string(),
            events: vec!["message".to_string()],
            verification: WebhookVerification::Ed25519Signature {
                public_key_header: "X-Key".to_string(),
            },
            retry_policy: RetryConfig::default(),
        };
        let json = serde_json::to_string(&recipe).unwrap();
        let decoded: WebhookRecipe = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.registration_url, recipe.registration_url);
        assert_eq!(decoded.events.len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Complex multi-step recipe (integration-style)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn complex_oauth_recipe_roundtrip() {
        let recipe = ProvisioningRecipe::new(
            RecipeId::new("discord/oauth"),
            "1",
            "Set up Discord bot with OAuth",
        )
        .with_step(
            ProvisioningStep::new(
                StepId::new("oauth_flow"),
                ProvisioningStepType::Oauth {
                    flow: OAuthRecipe::AuthorizationCodePkce {
                        authorization_url: "https://discord.com/oauth2/authorize".to_string(),
                        token_url: "https://discord.com/api/oauth2/token".to_string(),
                        scopes: vec!["bot".to_string(), "applications.commands".to_string()],
                        auto_browser: true,
                        callback_port: 8080,
                    },
                },
            )
            .with_approval(),
        )
        .with_step(
            ProvisioningStep::new(
                StepId::new("store_token"),
                ProvisioningStepType::StoreSecret {
                    key: "discord_token".to_string(),
                    value_from: StepId::new("oauth_flow"),
                    scope: "connector:fcp.discord".to_string(),
                },
            )
            .depends_on(StepId::new("oauth_flow")),
        )
        .with_step(
            ProvisioningStep::new(
                StepId::new("webhook"),
                ProvisioningStepType::Webhook {
                    registration: WebhookRecipe {
                        registration_url: "https://discord.com/api/webhooks".to_string(),
                        events: vec!["MESSAGE_CREATE".to_string()],
                        verification: WebhookVerification::Ed25519Signature {
                            public_key_header: "X-Signature-Ed25519".to_string(),
                        },
                        retry_policy: RetryConfig::default(),
                    },
                },
            )
            .depends_on(StepId::new("store_token")),
        );

        let json = serde_json::to_string_pretty(&recipe).unwrap();
        let decoded: ProvisioningRecipe = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.steps.len(), 3);
        assert!(decoded.steps[0].requires_approval);
        assert_eq!(decoded.steps[1].depends_on.len(), 1);
        assert_eq!(decoded.steps[2].depends_on.len(), 1);
    }

    #[test]
    fn telegram_bot_recipe_roundtrip() {
        let recipe =
            ProvisioningRecipe::new(RecipeId::new("telegram/bot"), "1", "Set up Telegram bot")
                .with_step(ProvisioningStep::new(
                    StepId::new("open_botfather"),
                    ProvisioningStepType::OpenUrl {
                        url: "https://t.me/BotFather".to_string(),
                    },
                ))
                .with_step(
                    ProvisioningStep::new(
                        StepId::new("enter_token"),
                        ProvisioningStepType::PromptSecret {
                            message: "Paste the bot token from BotFather".to_string(),
                        },
                    )
                    .depends_on(StepId::new("open_botfather")),
                )
                .with_step(
                    ProvisioningStep::new(
                        StepId::new("save_token"),
                        ProvisioningStepType::StoreSecret {
                            key: "bot_token".to_string(),
                            value_from: StepId::new("enter_token"),
                            scope: "connector:fcp.telegram".to_string(),
                        },
                    )
                    .depends_on(StepId::new("enter_token")),
                );

        let json = serde_json::to_string(&recipe).unwrap();
        let decoded: ProvisioningRecipe = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id.as_str(), "telegram/bot");
        assert_eq!(decoded.steps.len(), 3);
    }
}
