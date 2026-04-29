//! Automation recipes and provisioning interface (NORMATIVE).
//!
//! Implements the recipe model and provisioning workflow described in
//! `FCP_Specification_V3.md` §10.4 (Provisioning and Automation Recipes). This is the standard connector-facing
//! interface for automated setup (OAuth, webhooks, secret capture) with
//! minimal human prompts and deterministic, idempotent steps.

use std::{error::Error, fmt};

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

/// Opaque token identifying a completed human-consent step.
///
/// A `ConsentToken` is an identifier, not raw OAuth credential material. It is
/// intentionally displayable so provisioning receipts, audit references, and
/// operator logs can point at the consent decision without exposing secrets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConsentToken(String);

impl ConsentToken {
    const MAX_LEN: usize = 256;

    /// Create a new consent token identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ConsentTokenParseError`] if the token is empty, too long, or
    /// contains non-display-safe characters.
    pub fn new(token: impl Into<String>) -> Result<Self, ConsentTokenParseError> {
        Self::try_from(token.into())
    }

    /// Return the token identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConsentToken {
    type Error = ConsentTokenParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_consent_token(&value)?;
        Ok(Self(value))
    }
}

impl From<ConsentToken> for String {
    fn from(value: ConsentToken) -> Self {
        value.0
    }
}

impl std::str::FromStr for ConsentToken {
    type Err = ConsentTokenParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl fmt::Display for ConsentToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn validate_consent_token(value: &str) -> Result<(), ConsentTokenParseError> {
    if value.is_empty() {
        return Err(ConsentTokenParseError::Empty);
    }

    if value.len() > ConsentToken::MAX_LEN {
        return Err(ConsentTokenParseError::TooLong {
            len: value.len(),
            max: ConsentToken::MAX_LEN,
        });
    }

    for (index, ch) in value.char_indices() {
        let valid = ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':');
        if !valid {
            return Err(ConsentTokenParseError::InvalidChar { ch, index });
        }
    }

    Ok(())
}

/// Error returned when parsing a [`ConsentToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentTokenParseError {
    /// The token was empty.
    Empty,
    /// The token exceeded the maximum supported byte length.
    TooLong {
        /// Actual token length in bytes.
        len: usize,
        /// Maximum supported token length in bytes.
        max: usize,
    },
    /// The token contained a character outside the display-safe grammar.
    InvalidChar {
        /// Invalid character.
        ch: char,
        /// Byte index of the invalid character.
        index: usize,
    },
}

impl fmt::Display for ConsentTokenParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("consent token must not be empty"),
            Self::TooLong { len, max } => {
                write!(f, "consent token too long ({len} bytes > {max} bytes)")
            }
            Self::InvalidChar { ch, index } => write!(
                f,
                "consent token contains invalid character '{ch}' at byte {index}"
            ),
        }
    }
}

impl Error for ConsentTokenParseError {}

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

impl fmt::Display for ProvisioningRecipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let step_label = if self.steps.len() == 1 {
            "step"
        } else {
            "steps"
        };
        write!(
            f,
            "{}@{}: {} ({} {step_label})",
            self.id,
            self.version,
            self.description,
            self.steps.len()
        )
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

impl ProvisioningStepType {
    /// Return the canonical step-kind display and serde tag.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PromptUser { .. } => "prompt_user",
            Self::PromptSecret { .. } => "prompt_secret",
            Self::OpenUrl { .. } => "open_url",
            Self::StoreSecret { .. } => "store_secret",
            Self::Oauth { .. } => "oauth",
            Self::Webhook { .. } => "webhook",
        }
    }
}

impl fmt::Display for ProvisioningStepType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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

/// Port number validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortNumberValidationError {
    /// The numeric port is outside the inclusive TCP/UDP port range.
    OutOfRange {
        /// The provided port value.
        value: i64,
        /// The minimum accepted port number.
        min: u16,
        /// The maximum accepted port number.
        max: u16,
    },
}

impl fmt::Display for PortNumberValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { value, min, max } => {
                write!(f, "port number {value} is outside range {min}..={max}")
            }
        }
    }
}

impl Error for PortNumberValidationError {}

/// Validate a numeric TCP/UDP port and return the canonical `u16` value.
///
/// Port `0` is accepted because callers may use it to request OS-assigned
/// ephemeral ports. Privileged ports are accepted; authorization policy belongs
/// at the call site.
///
/// # Errors
///
/// Returns [`PortNumberValidationError::OutOfRange`] when `port` is negative or
/// greater than `u16::MAX`.
pub fn validate_port_number(port: i64) -> Result<u16, PortNumberValidationError> {
    u16::try_from(port).map_err(|_| PortNumberValidationError::OutOfRange {
        value: port,
        min: 0,
        max: u16::MAX,
    })
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
    use async_trait::async_trait;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    use std::time::Instant;

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

    #[derive(Debug)]
    struct MockProvisioner {
        recipe: ProvisioningRecipe,
        state: ProvisioningState,
        descriptor: SetupDescriptor,
        approvals: HashSet<StepId>,
        prompted_values: HashMap<StepId, String>,
        stored_secrets: HashMap<String, String>,
        webhook_registrations: Vec<(String, Vec<String>)>,
        step_logs: Vec<serde_json::Value>,
    }

    impl MockProvisioner {
        fn new(recipe: ProvisioningRecipe) -> Self {
            let human_prompts = recipe
                .steps
                .iter()
                .flat_map(|step| {
                    let mut prompts = Vec::new();
                    if step.requires_approval {
                        prompts.push(HumanPrompt {
                            step_id: step.id.clone(),
                            prompt_type: HumanPromptType::Approval,
                            message: format!("Approve provisioning step {}", step.id.as_str()),
                            url: None,
                        });
                    }
                    match &step.kind {
                        ProvisioningStepType::PromptSecret { message } => {
                            prompts.push(HumanPrompt {
                                step_id: step.id.clone(),
                                prompt_type: HumanPromptType::Secret,
                                message: message.clone(),
                                url: None,
                            });
                        }
                        ProvisioningStepType::PromptUser { message } => {
                            prompts.push(HumanPrompt {
                                step_id: step.id.clone(),
                                prompt_type: HumanPromptType::Text,
                                message: message.clone(),
                                url: None,
                            });
                        }
                        ProvisioningStepType::OpenUrl { url } => {
                            prompts.push(HumanPrompt {
                                step_id: step.id.clone(),
                                prompt_type: HumanPromptType::Url,
                                message: "Open URL".to_string(),
                                url: Some(url.clone()),
                            });
                        }
                        _ => {}
                    }
                    prompts
                })
                .collect();

            Self {
                descriptor: SetupDescriptor {
                    tool_descriptor: json!({"name":"mock.provision","kind":"test"}),
                    human_prompts,
                    estimated_duration_ms: Some(500),
                },
                state: ProvisioningState {
                    status: ProvisioningStatus::NotStarted,
                    current_step: None,
                    completed_steps: Vec::new(),
                    remaining_steps: recipe.steps.iter().map(|step| step.id.clone()).collect(),
                    awaiting_human: Vec::new(),
                    error_message: None,
                },
                recipe,
                approvals: HashSet::new(),
                prompted_values: HashMap::new(),
                stored_secrets: HashMap::new(),
                webhook_registrations: Vec::new(),
                step_logs: Vec::new(),
            }
        }

        fn approve_step(&mut self, step_id: &str) {
            self.approvals.insert(StepId::new(step_id));
        }

        fn set_prompt_value(&mut self, step_id: &str, value: &str) {
            let sid = StepId::new(step_id);
            self.prompted_values.insert(sid.clone(), value.to_string());
            self.mark_completed(&sid);
        }

        fn remove_awaiting_prompt(&mut self, step_id: &StepId) {
            self.state
                .awaiting_human
                .retain(|prompt| prompt.step_id != *step_id);
        }

        fn mark_completed(&mut self, step_id: &StepId) {
            if !self.state.completed_steps.contains(step_id) {
                self.state.completed_steps.push(step_id.clone());
            }
            self.state
                .remaining_steps
                .retain(|remaining| remaining != step_id);
            self.remove_awaiting_prompt(step_id);
            self.state.current_step = Some(step_id.clone());
            self.state.status = if self.state.remaining_steps.is_empty() {
                ProvisioningStatus::Completed
            } else {
                ProvisioningStatus::InProgress
            };
        }

        #[allow(clippy::too_many_arguments)]
        fn log_step(
            &mut self,
            step_id: &StepId,
            outcome: &str,
            requires_approval: bool,
            prompt_type: Option<&str>,
            error_message: Option<&str>,
            recovery_hint: Option<&str>,
            started: Instant,
        ) {
            self.step_logs.push(json!({
                "recipe_id": self.recipe.id.as_str(),
                "step_name": step_id.as_str(),
                "outcome": outcome,
                "requires_approval": requires_approval,
                "prompt_type": prompt_type,
                "error_message": error_message,
                "recovery_hint": recovery_hint,
                "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "logged_at": chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            }));
        }
    }

    #[async_trait]
    impl ProvisioningInterface for MockProvisioner {
        fn describe_setup(&self) -> SetupDescriptor {
            self.descriptor.clone()
        }

        fn get_state(&self) -> ProvisioningState {
            self.state.clone()
        }

        #[allow(clippy::too_many_lines)]
        async fn execute_step(
            &mut self,
            step_id: StepId,
        ) -> Result<ProvisioningStepResult, FcpError> {
            let started = Instant::now();
            let step = self
                .recipe
                .steps
                .iter()
                .find(|candidate| candidate.id == step_id)
                .cloned()
                .ok_or_else(|| FcpError::ResourceNotFound {
                    resource: format!("provisioning_step:{}", step_id.as_str()),
                })?;

            self.state.current_step = Some(step.id.clone());
            self.state.status = ProvisioningStatus::InProgress;

            let missing_dependencies = step
                .depends_on
                .iter()
                .filter(|dependency| !self.state.completed_steps.contains(dependency))
                .map(|dependency| dependency.as_str().to_string())
                .collect::<Vec<_>>();
            if !missing_dependencies.is_empty() {
                let dependency_list = missing_dependencies.join(", ");
                let error_message = format!(
                    "step {} is blocked by incomplete dependencies: {dependency_list}",
                    step.id.as_str()
                );
                let recovery_hint = format!("Complete prerequisite steps first: {dependency_list}");
                self.log_step(
                    &step.id,
                    "blocked_dependency",
                    step.requires_approval,
                    None,
                    Some(error_message.as_str()),
                    Some(recovery_hint.as_str()),
                    started,
                );
                return Err(FcpError::Conflict {
                    message: error_message,
                });
            }

            if step.requires_approval && !self.approvals.contains(&step.id) {
                let prompt = HumanPrompt {
                    step_id: step.id.clone(),
                    prompt_type: HumanPromptType::Approval,
                    message: format!("Approve provisioning step {}", step.id.as_str()),
                    url: None,
                };
                self.state.status = ProvisioningStatus::AwaitingUser;
                self.state.awaiting_human.push(prompt.clone());
                self.log_step(
                    &step.id,
                    "awaiting_approval",
                    step.requires_approval,
                    Some("approval"),
                    None,
                    None,
                    started,
                );
                return Ok(ProvisioningStepResult::AwaitingHuman { prompt });
            }

            match step.kind {
                ProvisioningStepType::PromptUser { message } => {
                    let prompt = HumanPrompt {
                        step_id: step.id.clone(),
                        prompt_type: HumanPromptType::Text,
                        message,
                        url: None,
                    };
                    self.state.status = ProvisioningStatus::AwaitingUser;
                    self.state.awaiting_human.push(prompt.clone());
                    self.log_step(
                        &step.id,
                        "awaiting_input",
                        step.requires_approval,
                        Some("text"),
                        None,
                        None,
                        started,
                    );
                    Ok(ProvisioningStepResult::AwaitingHuman { prompt })
                }
                ProvisioningStepType::PromptSecret { message } => {
                    let prompt = HumanPrompt {
                        step_id: step.id.clone(),
                        prompt_type: HumanPromptType::Secret,
                        message,
                        url: None,
                    };
                    self.state.status = ProvisioningStatus::AwaitingUser;
                    self.state.awaiting_human.push(prompt.clone());
                    self.log_step(
                        &step.id,
                        "awaiting_secret",
                        step.requires_approval,
                        Some("secret"),
                        None,
                        None,
                        started,
                    );
                    Ok(ProvisioningStepResult::AwaitingHuman { prompt })
                }
                ProvisioningStepType::OpenUrl { url } => {
                    let prompt = HumanPrompt {
                        step_id: step.id.clone(),
                        prompt_type: HumanPromptType::Url,
                        message: "Open URL".to_string(),
                        url: Some(url),
                    };
                    self.state.status = ProvisioningStatus::AwaitingUser;
                    self.state.awaiting_human.push(prompt.clone());
                    self.log_step(
                        &step.id,
                        "awaiting_url",
                        step.requires_approval,
                        Some("url"),
                        None,
                        None,
                        started,
                    );
                    Ok(ProvisioningStepResult::AwaitingHuman { prompt })
                }
                ProvisioningStepType::StoreSecret {
                    key, value_from, ..
                } => {
                    let value =
                        self.prompted_values
                            .get(&value_from)
                            .cloned()
                            .ok_or_else(|| {
                                let error_message =
                                    format!("missing prompted value for {}", value_from.as_str());
                                self.state.status = ProvisioningStatus::Failed;
                                self.state.error_message = Some(error_message.clone());
                                self.log_step(
                                    &step.id,
                                    "failed",
                                    step.requires_approval,
                                    None,
                                    Some(error_message.as_str()),
                                    Some(
                                        "Execute the prerequisite prompt step before store_secret",
                                    ),
                                    started,
                                );
                                FcpError::ResourceNotFound {
                                    resource: format!("prompt_value:{}", value_from.as_str()),
                                }
                            })?;

                    self.stored_secrets.insert(key, value);
                    self.mark_completed(&step.id);
                    self.log_step(
                        &step.id,
                        "completed",
                        step.requires_approval,
                        None,
                        None,
                        None,
                        started,
                    );
                    Ok(ProvisioningStepResult::Completed { step_id: step.id })
                }
                ProvisioningStepType::Oauth { .. } => {
                    self.mark_completed(&step.id);
                    self.log_step(
                        &step.id,
                        "completed",
                        step.requires_approval,
                        None,
                        None,
                        None,
                        started,
                    );
                    Ok(ProvisioningStepResult::Completed { step_id: step.id })
                }
                ProvisioningStepType::Webhook { registration } => {
                    self.webhook_registrations
                        .push((registration.registration_url, registration.events));
                    self.mark_completed(&step.id);
                    self.log_step(
                        &step.id,
                        "completed",
                        step.requires_approval,
                        None,
                        None,
                        None,
                        started,
                    );
                    Ok(ProvisioningStepResult::Completed { step_id: step.id })
                }
            }
        }

        fn validate(&self) -> ProvisioningValidation {
            if self.state.error_message.is_some() {
                return ProvisioningValidation::failed(vec![
                    self.state
                        .error_message
                        .clone()
                        .unwrap_or_else(|| "unknown provisioning failure".to_string()),
                ]);
            }

            if self.state.remaining_steps.is_empty() {
                ProvisioningValidation::ok()
            } else {
                ProvisioningValidation::failed(vec![format!(
                    "{} steps still pending",
                    self.state.remaining_steps.len()
                )])
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn provisioning_interface_executes_host_mediated_setup_flow() {
        fcp_async_core::runtime::block_on_sync(async {
            let recipe = ProvisioningRecipe::new(
                RecipeId::new("discord/setup"),
                "1",
                "Mock Discord setup for integration-style tests",
            )
            .with_step(ProvisioningStep::new(
                StepId::new("oauth"),
                ProvisioningStepType::Oauth {
                    flow: OAuthRecipe::AuthorizationCodePkce {
                        authorization_url: "https://auth.example.test/oauth/authorize".to_string(),
                        token_url: "https://auth.example.test/oauth/token".to_string(),
                        scopes: vec!["bot".to_string()],
                        auto_browser: false,
                        callback_port: 3000,
                    },
                },
            ))
            .with_step(ProvisioningStep::new(
                StepId::new("webhook"),
                ProvisioningStepType::Webhook {
                    registration: WebhookRecipe {
                        registration_url: "https://api.example.test/webhooks".to_string(),
                        events: vec!["message.create".to_string(), "guild.join".to_string()],
                        verification: WebhookVerification::ChallengeResponse {
                            challenge_param: "challenge".to_string(),
                        },
                        retry_policy: RetryConfig::default(),
                    },
                },
            ))
            .with_step(ProvisioningStep::new(
                StepId::new("prompt_secret"),
                ProvisioningStepType::PromptSecret {
                    message: "Paste connector token".to_string(),
                },
            ))
            .with_step(
                ProvisioningStep::new(
                    StepId::new("store_secret"),
                    ProvisioningStepType::StoreSecret {
                        key: "connector_token".to_string(),
                        value_from: StepId::new("prompt_secret"),
                        scope: "connector:fcp.discord".to_string(),
                    },
                )
                .depends_on(StepId::new("prompt_secret")),
            );

            let mut provisioner = MockProvisioner::new(recipe);
            let setup = provisioner.describe_setup();
            assert_eq!(setup.estimated_duration_ms, Some(500));
            assert_eq!(setup.tool_descriptor["name"], "mock.provision");

            let oauth_result = provisioner
                .execute_step(StepId::new("oauth"))
                .await
                .unwrap();
            assert!(matches!(
                oauth_result,
                ProvisioningStepResult::Completed { .. }
            ));

            let webhook_result = provisioner
                .execute_step(StepId::new("webhook"))
                .await
                .unwrap();
            assert!(matches!(
                webhook_result,
                ProvisioningStepResult::Completed { .. }
            ));
            assert_eq!(provisioner.webhook_registrations.len(), 1);
            assert_eq!(
                provisioner.webhook_registrations[0].0,
                "https://api.example.test/webhooks"
            );

            let prompt_result = provisioner
                .execute_step(StepId::new("prompt_secret"))
                .await
                .unwrap();
            let ProvisioningStepResult::AwaitingHuman { prompt } = prompt_result else {
                panic!("expected prompting for secret input")
            };
            assert_eq!(prompt.prompt_type, HumanPromptType::Secret);
            assert_eq!(
                provisioner.get_state().status,
                ProvisioningStatus::AwaitingUser
            );

            provisioner.set_prompt_value("prompt_secret", "super-secret-token");
            let store_result = provisioner
                .execute_step(StepId::new("store_secret"))
                .await
                .unwrap();
            assert!(matches!(
                store_result,
                ProvisioningStepResult::Completed { .. }
            ));

            let validation = provisioner.validate();
            assert!(validation.valid);
            assert_eq!(
                provisioner.get_state().status,
                ProvisioningStatus::Completed
            );

            let logs = serde_json::to_string(&provisioner.step_logs).unwrap();
            assert!(logs.contains("\"recipe_id\":\"discord/setup\""));
            assert!(logs.contains("\"step_name\":\"webhook\""));
            assert!(!logs.contains("super-secret-token"));
            assert_eq!(provisioner.step_logs.len(), 4);
            let prompt_secret_log = provisioner
                .step_logs
                .iter()
                .find(|entry| entry["step_name"] == "prompt_secret")
                .expect("prompt_secret log should exist");
            assert_eq!(prompt_secret_log["prompt_type"], "secret");
            assert_eq!(prompt_secret_log["outcome"], "awaiting_secret");
            assert!(
                prompt_secret_log["duration_ms"].as_u64().is_some(),
                "duration_ms should be captured for structured setup logs"
            );
            assert!(
                prompt_secret_log["logged_at"].as_str().is_some(),
                "logged_at timestamp should be present"
            );
        })
        .expect("runtime should execute provisioning setup flow");
    }

    #[test]
    fn provisioning_interface_requires_approval_for_privileged_step() {
        fcp_async_core::runtime::block_on_sync(async {
            let recipe = ProvisioningRecipe::new(
                RecipeId::new("discord/privileged"),
                "1",
                "Privileged setup with approval",
            )
            .with_step(
                ProvisioningStep::new(
                    StepId::new("register_webhook"),
                    ProvisioningStepType::Webhook {
                        registration: WebhookRecipe {
                            registration_url: "https://api.example.test/webhooks".to_string(),
                            events: vec!["message.create".to_string()],
                            verification: WebhookVerification::ChallengeResponse {
                                challenge_param: "challenge".to_string(),
                            },
                            retry_policy: RetryConfig::default(),
                        },
                    },
                )
                .with_approval(),
            );

            let mut provisioner = MockProvisioner::new(recipe);
            let first = provisioner
                .execute_step(StepId::new("register_webhook"))
                .await
                .unwrap();

            let ProvisioningStepResult::AwaitingHuman { prompt } = first else {
                panic!("expected approval prompt")
            };
            assert_eq!(prompt.prompt_type, HumanPromptType::Approval);
            assert_eq!(
                provisioner.get_state().status,
                ProvisioningStatus::AwaitingUser
            );

            provisioner.approve_step("register_webhook");
            let second = provisioner
                .execute_step(StepId::new("register_webhook"))
                .await
                .unwrap();
            assert!(matches!(second, ProvisioningStepResult::Completed { .. }));
            assert!(provisioner.get_state().awaiting_human.is_empty());
            assert_eq!(
                provisioner.get_state().status,
                ProvisioningStatus::Completed
            );
            assert_eq!(provisioner.step_logs.len(), 2);
            assert_eq!(provisioner.step_logs[0]["outcome"], "awaiting_approval");
            assert_eq!(provisioner.step_logs[0]["prompt_type"], "approval");
            assert_eq!(provisioner.step_logs[0]["requires_approval"], true);
            assert_eq!(provisioner.step_logs[1]["outcome"], "completed");
            assert!(
                provisioner.step_logs[1]["duration_ms"].as_u64().is_some(),
                "approval completion log should include duration_ms"
            );
        })
        .expect("runtime should execute privileged approval flow");
    }

    #[test]
    fn provisioning_validation_fails_when_required_secret_is_missing() {
        fcp_async_core::runtime::block_on_sync(async {
            let recipe = ProvisioningRecipe::new(
                RecipeId::new("discord/missing-secret"),
                "1",
                "Store secret without collecting it first",
            )
            .with_step(ProvisioningStep::new(
                StepId::new("store_secret"),
                ProvisioningStepType::StoreSecret {
                    key: "connector_token".to_string(),
                    value_from: StepId::new("prompt_secret"),
                    scope: "connector:fcp.discord".to_string(),
                },
            ));

            let mut provisioner = MockProvisioner::new(recipe);
            let error = provisioner
                .execute_step(StepId::new("store_secret"))
                .await
                .expect_err("store secret should fail without prompted value");
            assert!(matches!(error, FcpError::ResourceNotFound { .. }));

            let validation = provisioner.validate();
            assert!(!validation.valid);
            assert!(!validation.errors.is_empty());
            assert_eq!(provisioner.get_state().status, ProvisioningStatus::Failed);
            assert_eq!(provisioner.step_logs.len(), 1);
            assert_eq!(provisioner.step_logs[0]["outcome"], "failed");
            assert!(
                provisioner.step_logs[0]["error_message"]
                    .as_str()
                    .expect("failed provisioning log should carry error details")
                    .contains("missing prompted value")
            );
            assert_eq!(
                provisioner.step_logs[0]["recovery_hint"],
                "Execute the prerequisite prompt step before store_secret"
            );
        })
        .expect("runtime should execute missing secret validation");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RecipeId — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn recipe_id_hash_key() {
        let mut map = HashMap::new();
        map.insert(RecipeId::new("a"), 1);
        map.insert(RecipeId::new("b"), 2);
        map.insert(RecipeId::new("a"), 3);
        assert_eq!(map.len(), 2);
        assert_eq!(map[&RecipeId::new("a")], 3);
    }

    #[test]
    fn recipe_id_debug_format() {
        let id = RecipeId::new("debug/test");
        let debug = format!("{id:?}");
        assert!(debug.contains("debug/test"));
    }

    #[test]
    fn recipe_id_empty_string() {
        let id = RecipeId::new("");
        assert_eq!(id.as_str(), "");
        assert_eq!(format!("{id}"), "");
    }

    #[test]
    fn recipe_id_unicode() {
        let id = RecipeId::new("setup/\u{1f680}");
        assert!(id.as_str().contains('\u{1f680}'));
        let json = serde_json::to_string(&id).unwrap();
        let decoded: RecipeId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StepId — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn step_id_equality_and_inequality() {
        let a = StepId::new("same");
        let b = StepId::new("same");
        let c = StepId::new("other");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn step_id_clone() {
        let original = StepId::new("cloned");
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn step_id_debug_format() {
        let id = StepId::new("enter_token");
        let debug = format!("{id:?}");
        assert!(debug.contains("enter_token"));
    }

    #[test]
    fn step_id_empty_string() {
        let id = StepId::new("");
        assert_eq!(id.as_str(), "");
    }

    #[test]
    fn step_id_deserialize_from_json_string() {
        let decoded: StepId = serde_json::from_str("\"my_step_id\"").unwrap();
        assert_eq!(decoded.as_str(), "my_step_id");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningRecipe — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn recipe_clone_preserves_steps() {
        let recipe = ProvisioningRecipe::new(RecipeId::new("orig"), "1", "Original").with_step(
            ProvisioningStep::new(
                StepId::new("s1"),
                ProvisioningStepType::PromptUser {
                    message: "Hi".to_string(),
                },
            ),
        );
        let cloned = recipe.clone();
        assert_eq!(recipe.id, cloned.id);
        assert_eq!(recipe.steps.len(), cloned.steps.len());
        assert_eq!(recipe.version, cloned.version);
        assert_eq!(recipe.description, cloned.description);
    }

    #[test]
    fn recipe_debug_format() {
        let recipe = ProvisioningRecipe::new(RecipeId::new("dbg"), "1", "Debug recipe");
        let debug = format!("{recipe:?}");
        assert!(debug.contains("dbg"));
        assert!(debug.contains("Debug recipe"));
    }

    #[test]
    fn recipe_deserialize_without_steps_field() {
        let json = r#"{"id":"test","version":"1","description":"No steps key"}"#;
        let decoded: ProvisioningRecipe = serde_json::from_str(json).unwrap();
        assert!(decoded.steps.is_empty());
        assert_eq!(decoded.id.as_str(), "test");
    }

    #[test]
    fn recipe_with_multiple_chained_steps() {
        let recipe = ProvisioningRecipe::new(RecipeId::new("chain"), "1", "Chain")
            .with_step(ProvisioningStep::new(
                StepId::new("a"),
                ProvisioningStepType::PromptUser {
                    message: "A".to_string(),
                },
            ))
            .with_step(ProvisioningStep::new(
                StepId::new("b"),
                ProvisioningStepType::PromptUser {
                    message: "B".to_string(),
                },
            ))
            .with_step(ProvisioningStep::new(
                StepId::new("c"),
                ProvisioningStepType::PromptUser {
                    message: "C".to_string(),
                },
            ));
        assert_eq!(recipe.steps.len(), 3);
        assert_eq!(recipe.steps[2].id.as_str(), "c");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningStep — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn step_serde_with_depends_on_present() {
        let step = ProvisioningStep::new(
            StepId::new("s2"),
            ProvisioningStepType::PromptUser {
                message: "After s1".to_string(),
            },
        )
        .depends_on(StepId::new("s1"));
        let value = serde_json::to_value(&step).unwrap();
        let deps = value["depends_on"].as_array().unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0], "s1");

        let decoded: ProvisioningStep = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.depends_on.len(), 1);
        assert_eq!(decoded.depends_on[0].as_str(), "s1");
    }

    #[test]
    fn step_serde_with_requires_approval_true() {
        let step = ProvisioningStep::new(
            StepId::new("approve_me"),
            ProvisioningStepType::PromptUser {
                message: "Need approval".to_string(),
            },
        )
        .with_approval();
        let value = serde_json::to_value(&step).unwrap();
        assert!(value["requires_approval"].as_bool().unwrap());

        let decoded: ProvisioningStep = serde_json::from_value(value).unwrap();
        assert!(decoded.requires_approval);
    }

    #[test]
    fn step_clone_preserves_all_fields() {
        let step = ProvisioningStep::new(
            StepId::new("orig"),
            ProvisioningStepType::PromptSecret {
                message: "Token".to_string(),
            },
        )
        .with_approval()
        .depends_on(StepId::new("prev"));
        let cloned = step.clone();
        assert_eq!(step.id, cloned.id);
        assert_eq!(step.requires_approval, cloned.requires_approval);
        assert_eq!(step.depends_on.len(), cloned.depends_on.len());
    }

    #[test]
    fn step_default_requires_approval_false_in_json() {
        let step = ProvisioningStep::new(
            StepId::new("s"),
            ProvisioningStepType::PromptUser {
                message: "Hi".to_string(),
            },
        );
        let value = serde_json::to_value(&step).unwrap();
        assert_eq!(value["requires_approval"], false);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OAuthRecipe — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn oauth_device_code_empty_scopes_omitted() {
        let flow = OAuthRecipe::DeviceCode {
            device_authorization_url: "https://auth.example.com/device".to_string(),
            token_url: "https://auth.example.com/token".to_string(),
            scopes: Vec::new(),
            poll_interval_seconds: 5,
        };
        let value = serde_json::to_value(&flow).unwrap();
        assert!(value.get("scopes").is_none());
    }

    #[test]
    fn oauth_client_credentials_empty_scopes_omitted() {
        let flow = OAuthRecipe::ClientCredentials {
            token_url: "https://auth.example.com/token".to_string(),
            scopes: Vec::new(),
        };
        let value = serde_json::to_value(&flow).unwrap();
        assert!(value.get("scopes").is_none());
    }

    #[test]
    fn oauth_pkce_auto_browser_default_false_roundtrip() {
        let json = r#"{"type":"authorization_code_pkce","authorization_url":"https://a.test/auth","token_url":"https://a.test/token","callback_port":9090}"#;
        let decoded: OAuthRecipe = serde_json::from_str(json).unwrap();
        match decoded {
            OAuthRecipe::AuthorizationCodePkce {
                auto_browser,
                callback_port,
                scopes,
                ..
            } => {
                assert!(!auto_browser);
                assert_eq!(callback_port, 9090);
                assert!(scopes.is_empty());
            }
            _ => panic!("expected AuthorizationCodePkce"),
        }
    }

    #[test]
    fn oauth_recipe_clone() {
        let flow = OAuthRecipe::AuthorizationCodePkce {
            authorization_url: "https://a.test/auth".to_string(),
            token_url: "https://a.test/token".to_string(),
            scopes: vec!["read".to_string()],
            auto_browser: true,
            callback_port: 8080,
        };
        let cloned = flow.clone();
        let orig_json = serde_json::to_value(&flow).unwrap();
        let clone_json = serde_json::to_value(&cloned).unwrap();
        assert_eq!(orig_json, clone_json);
    }

    #[test]
    fn oauth_recipe_debug() {
        let flow = OAuthRecipe::ClientCredentials {
            token_url: "https://auth.example.com/token".to_string(),
            scopes: vec!["api".to_string()],
        };
        let debug = format!("{flow:?}");
        assert!(debug.contains("ClientCredentials"));
        assert!(debug.contains("api"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WebhookVerification — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn webhook_verification_clone() {
        let ver = WebhookVerification::HmacSignature {
            algorithm: "sha256".to_string(),
            header: "X-Signature".to_string(),
        };
        let cloned = ver.clone();
        let orig_json = serde_json::to_value(&ver).unwrap();
        let clone_json = serde_json::to_value(&cloned).unwrap();
        assert_eq!(orig_json, clone_json);
    }

    #[test]
    fn webhook_verification_debug() {
        let ver = WebhookVerification::ChallengeResponse {
            challenge_param: "hub.challenge".to_string(),
        };
        let debug = format!("{ver:?}");
        assert!(debug.contains("ChallengeResponse"));
    }

    #[test]
    fn webhook_verification_all_variants_roundtrip() {
        let variants: Vec<WebhookVerification> = vec![
            WebhookVerification::HmacSignature {
                algorithm: "sha512".to_string(),
                header: "X-Sig".to_string(),
            },
            WebhookVerification::ChallengeResponse {
                challenge_param: "verify_token".to_string(),
            },
            WebhookVerification::Ed25519Signature {
                public_key_header: "X-PubKey".to_string(),
            },
        ];
        let expected_types = ["hmac_signature", "challenge_response", "ed25519_signature"];
        for (ver, expected_type) in variants.iter().zip(expected_types.iter()) {
            let json = serde_json::to_string(ver).unwrap();
            let decoded: WebhookVerification = serde_json::from_str(&json).unwrap();
            let value = serde_json::to_value(&decoded).unwrap();
            assert_eq!(value["type"], *expected_type);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningStatus — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provisioning_status_debug_all_variants() {
        let variants = [
            ProvisioningStatus::NotStarted,
            ProvisioningStatus::InProgress,
            ProvisioningStatus::AwaitingUser,
            ProvisioningStatus::Completed,
            ProvisioningStatus::Failed,
            ProvisioningStatus::Aborted,
        ];
        for status in &variants {
            let debug = format!("{status:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn provisioning_status_clone_via_copy() {
        let a = ProvisioningStatus::Failed;
        let b = a;
        let c = a;
        assert_eq!(b, c);
    }

    #[test]
    fn provisioning_status_inequality() {
        assert_ne!(
            ProvisioningStatus::NotStarted,
            ProvisioningStatus::Completed
        );
        assert_ne!(ProvisioningStatus::InProgress, ProvisioningStatus::Failed);
        assert_ne!(
            ProvisioningStatus::AwaitingUser,
            ProvisioningStatus::Aborted
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningState — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provisioning_state_clone() {
        let state = ProvisioningState {
            status: ProvisioningStatus::InProgress,
            current_step: Some(StepId::new("s1")),
            completed_steps: vec![StepId::new("s0")],
            remaining_steps: vec![StepId::new("s2")],
            awaiting_human: Vec::new(),
            error_message: Some("partial".to_string()),
        };
        let cloned = state.clone();
        assert_eq!(state.status, cloned.status);
        assert_eq!(
            state.current_step.as_ref().map(StepId::as_str),
            cloned.current_step.as_ref().map(StepId::as_str)
        );
        assert_eq!(state.completed_steps.len(), cloned.completed_steps.len());
        assert_eq!(state.error_message, cloned.error_message);
    }

    #[test]
    fn provisioning_state_serde_error_roundtrip() {
        let state = ProvisioningState {
            status: ProvisioningStatus::Failed,
            current_step: Some(StepId::new("bad_step")),
            completed_steps: Vec::new(),
            remaining_steps: vec![StepId::new("next")],
            awaiting_human: Vec::new(),
            error_message: Some("timeout after 30s".to_string()),
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: ProvisioningState = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, ProvisioningStatus::Failed);
        assert_eq!(decoded.error_message.as_deref(), Some("timeout after 30s"));
        assert_eq!(decoded.current_step.unwrap().as_str(), "bad_step");
        assert_eq!(decoded.remaining_steps.len(), 1);
    }

    #[test]
    fn provisioning_state_debug() {
        let state = ProvisioningState::new();
        let debug = format!("{state:?}");
        assert!(debug.contains("NotStarted"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningProgress — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provisioning_progress_with_awaiting_human() {
        let progress = ProvisioningProgress {
            current_step: Some(StepId::new("oauth")),
            completed: vec![StepId::new("prompt_user")],
            remaining: vec![StepId::new("store")],
            awaiting_human: vec![HumanPrompt {
                step_id: StepId::new("oauth"),
                prompt_type: HumanPromptType::Url,
                message: "Open OAuth page".to_string(),
                url: Some("https://example.com/auth".to_string()),
            }],
        };
        let json = serde_json::to_string(&progress).unwrap();
        let decoded: ProvisioningProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.awaiting_human.len(), 1);
        assert_eq!(decoded.awaiting_human[0].prompt_type, HumanPromptType::Url);
    }

    #[test]
    fn provisioning_progress_clone() {
        let progress = ProvisioningProgress {
            current_step: Some(StepId::new("s1")),
            completed: vec![StepId::new("s0")],
            remaining: Vec::new(),
            awaiting_human: Vec::new(),
        };
        let cloned = progress.clone();
        assert_eq!(
            progress.current_step.as_ref().map(StepId::as_str),
            cloned.current_step.as_ref().map(StepId::as_str)
        );
        assert_eq!(progress.completed.len(), cloned.completed.len());
    }

    #[test]
    fn provisioning_progress_debug() {
        let progress = ProvisioningProgress {
            current_step: None,
            completed: Vec::new(),
            remaining: Vec::new(),
            awaiting_human: Vec::new(),
        };
        let debug = format!("{progress:?}");
        assert!(debug.contains("ProvisioningProgress"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HumanPrompt / HumanPromptType — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn human_prompt_type_copy_semantics() {
        let a = HumanPromptType::Secret;
        let b = a;
        let c = a;
        assert_eq!(b, c);
    }

    #[test]
    fn human_prompt_type_debug() {
        let t = HumanPromptType::Approval;
        let debug = format!("{t:?}");
        assert!(debug.contains("Approval"));
    }

    #[test]
    fn human_prompt_clone() {
        let prompt = HumanPrompt {
            step_id: StepId::new("p1"),
            prompt_type: HumanPromptType::Text,
            message: "Enter name".to_string(),
            url: Some("https://example.com".to_string()),
        };
        let cloned = prompt.clone();
        assert_eq!(prompt.step_id, cloned.step_id);
        assert_eq!(prompt.message, cloned.message);
        assert_eq!(prompt.url, cloned.url);
    }

    #[test]
    fn human_prompt_debug() {
        let prompt = HumanPrompt {
            step_id: StepId::new("dbg"),
            prompt_type: HumanPromptType::Secret,
            message: "Token".to_string(),
            url: None,
        };
        let debug = format!("{prompt:?}");
        assert!(debug.contains("Token"));
        assert!(debug.contains("Secret"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SetupDescriptor — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn setup_descriptor_clone() {
        let desc = SetupDescriptor {
            tool_descriptor: json!({"name": "test"}),
            human_prompts: vec![HumanPrompt {
                step_id: StepId::new("s1"),
                prompt_type: HumanPromptType::Text,
                message: "Name?".to_string(),
                url: None,
            }],
            estimated_duration_ms: Some(5000),
        };
        let cloned = desc.clone();
        assert_eq!(desc.tool_descriptor, cloned.tool_descriptor);
        assert_eq!(desc.human_prompts.len(), cloned.human_prompts.len());
        assert_eq!(desc.estimated_duration_ms, cloned.estimated_duration_ms);
    }

    #[test]
    fn setup_descriptor_debug() {
        let desc = SetupDescriptor {
            tool_descriptor: json!({}),
            human_prompts: Vec::new(),
            estimated_duration_ms: None,
        };
        let debug = format!("{desc:?}");
        assert!(debug.contains("SetupDescriptor"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningStepResult — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn step_result_clone() {
        let result = ProvisioningStepResult::Completed {
            step_id: StepId::new("done"),
        };
        let cloned = result.clone();
        let orig_json = serde_json::to_value(&result).unwrap();
        let clone_json = serde_json::to_value(&cloned).unwrap();
        assert_eq!(orig_json, clone_json);
    }

    #[test]
    fn step_result_awaiting_human_roundtrip() {
        let result = ProvisioningStepResult::AwaitingHuman {
            prompt: HumanPrompt {
                step_id: StepId::new("consent"),
                prompt_type: HumanPromptType::Approval,
                message: "Allow?".to_string(),
                url: None,
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: ProvisioningStepResult = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            ProvisioningStepResult::AwaitingHuman { .. }
        ));
    }

    #[test]
    fn step_result_in_progress_roundtrip() {
        let result = ProvisioningStepResult::InProgress {
            step_id: StepId::new("polling"),
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: ProvisioningStepResult = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, ProvisioningStepResult::InProgress { .. }));
    }

    #[test]
    fn step_result_debug() {
        let result = ProvisioningStepResult::InProgress {
            step_id: StepId::new("running"),
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("InProgress"));
        assert!(debug.contains("running"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningValidation — additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validation_clone() {
        let v = ProvisioningValidation::failed(vec!["err1".to_string(), "err2".to_string()]);
        let cloned = v.clone();
        assert_eq!(v.valid, cloned.valid);
        assert_eq!(v.errors.len(), cloned.errors.len());
        assert_eq!(v.errors[0], cloned.errors[0]);
    }

    #[test]
    fn validation_serde_roundtrip_with_errors() {
        let v = ProvisioningValidation::failed(vec!["missing field".to_string()]);
        let json = serde_json::to_string(&v).unwrap();
        let decoded: ProvisioningValidation = serde_json::from_str(&json).unwrap();
        assert!(!decoded.valid);
        assert_eq!(decoded.errors, vec!["missing field"]);
    }

    #[test]
    fn validation_debug() {
        let v = ProvisioningValidation::ok();
        let debug = format!("{v:?}");
        assert!(debug.contains("valid"));
    }

    #[test]
    fn validation_failed_empty_errors() {
        let v = ProvisioningValidation::failed(Vec::new());
        assert!(!v.valid);
        assert!(v.errors.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Operations constants — exact values
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operations_start_exact_value() {
        assert_eq!(operations::START, "fcp.provision.start");
    }

    #[test]
    fn operations_poll_exact_value() {
        assert_eq!(operations::POLL, "fcp.provision.poll");
    }

    #[test]
    fn operations_complete_exact_value() {
        assert_eq!(operations::COMPLETE, "fcp.provision.complete");
    }

    #[test]
    fn operations_abort_exact_value() {
        assert_eq!(operations::ABORT, "fcp.provision.abort");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MockProvisioner — additional edge case coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn mock_provisioner_execute_unknown_step_returns_error() {
        fcp_async_core::runtime::block_on_sync(async {
            let recipe = ProvisioningRecipe::new(RecipeId::new("test"), "1", "Empty recipe");
            let mut provisioner = MockProvisioner::new(recipe);
            let err = provisioner
                .execute_step(StepId::new("nonexistent"))
                .await
                .expect_err("should fail for unknown step");
            assert!(matches!(err, FcpError::ResourceNotFound { .. }));
        })
        .expect("runtime should execute unknown step test");
    }

    #[test]
    fn mock_provisioner_prompt_user_flow() {
        fcp_async_core::runtime::block_on_sync(async {
            let recipe = ProvisioningRecipe::new(RecipeId::new("prompt-test"), "1", "Prompt test")
                .with_step(ProvisioningStep::new(
                    StepId::new("ask_name"),
                    ProvisioningStepType::PromptUser {
                        message: "Enter your name".to_string(),
                    },
                ));
            let mut provisioner = MockProvisioner::new(recipe);
            let result = provisioner
                .execute_step(StepId::new("ask_name"))
                .await
                .unwrap();
            let ProvisioningStepResult::AwaitingHuman { prompt } = result else {
                panic!("expected AwaitingHuman for PromptUser");
            };
            assert_eq!(prompt.prompt_type, HumanPromptType::Text);
            assert_eq!(prompt.message, "Enter your name");
            assert_eq!(
                provisioner.get_state().status,
                ProvisioningStatus::AwaitingUser
            );
            assert_eq!(provisioner.get_state().awaiting_human.len(), 1);
        })
        .expect("runtime should execute prompt user flow");
    }

    #[test]
    fn mock_provisioner_open_url_flow() {
        fcp_async_core::runtime::block_on_sync(async {
            let recipe = ProvisioningRecipe::new(RecipeId::new("url-test"), "1", "URL test")
                .with_step(ProvisioningStep::new(
                    StepId::new("open_link"),
                    ProvisioningStepType::OpenUrl {
                        url: "https://t.me/BotFather".to_string(),
                    },
                ));
            let mut provisioner = MockProvisioner::new(recipe);
            let result = provisioner
                .execute_step(StepId::new("open_link"))
                .await
                .unwrap();
            let ProvisioningStepResult::AwaitingHuman { prompt } = result else {
                panic!("expected AwaitingHuman for OpenUrl");
            };
            assert_eq!(prompt.prompt_type, HumanPromptType::Url);
            assert_eq!(prompt.url.as_deref(), Some("https://t.me/BotFather"));
            assert_eq!(
                provisioner.get_state().status,
                ProvisioningStatus::AwaitingUser
            );
        })
        .expect("runtime should execute open url flow");
    }

    #[test]
    fn mock_provisioner_describe_setup_collects_human_prompts() {
        let recipe = ProvisioningRecipe::new(RecipeId::new("desc-test"), "1", "Descriptor test")
            .with_step(ProvisioningStep::new(
                StepId::new("user"),
                ProvisioningStepType::PromptUser {
                    message: "Name?".to_string(),
                },
            ))
            .with_step(ProvisioningStep::new(
                StepId::new("secret"),
                ProvisioningStepType::PromptSecret {
                    message: "Token?".to_string(),
                },
            ))
            .with_step(ProvisioningStep::new(
                StepId::new("link"),
                ProvisioningStepType::OpenUrl {
                    url: "https://example.com".to_string(),
                },
            ))
            .with_step(ProvisioningStep::new(
                StepId::new("store"),
                ProvisioningStepType::StoreSecret {
                    key: "k".to_string(),
                    value_from: StepId::new("secret"),
                    scope: "s".to_string(),
                },
            ));
        let provisioner = MockProvisioner::new(recipe);
        let setup = provisioner.describe_setup();
        // StoreSecret does not produce a human prompt; the other 3 do
        assert_eq!(setup.human_prompts.len(), 3);
        assert_eq!(setup.human_prompts[0].prompt_type, HumanPromptType::Text);
        assert_eq!(setup.human_prompts[1].prompt_type, HumanPromptType::Secret);
        assert_eq!(setup.human_prompts[2].prompt_type, HumanPromptType::Url);
    }

    #[test]
    fn mock_provisioner_describe_setup_includes_approval_prompts() {
        let recipe = ProvisioningRecipe::new(
            RecipeId::new("approval-desc"),
            "1",
            "Descriptor includes approval interactions",
        )
        .with_step(
            ProvisioningStep::new(
                StepId::new("register_webhook"),
                ProvisioningStepType::Webhook {
                    registration: WebhookRecipe {
                        registration_url: "https://api.example.test/webhooks".to_string(),
                        events: vec!["message.create".to_string()],
                        verification: WebhookVerification::ChallengeResponse {
                            challenge_param: "challenge".to_string(),
                        },
                        retry_policy: RetryConfig::default(),
                    },
                },
            )
            .with_approval(),
        );

        let provisioner = MockProvisioner::new(recipe);
        let setup = provisioner.describe_setup();
        assert_eq!(setup.human_prompts.len(), 1);
        assert_eq!(
            setup.human_prompts[0].prompt_type,
            HumanPromptType::Approval
        );
        assert_eq!(setup.human_prompts[0].step_id.as_str(), "register_webhook");
        assert!(setup.human_prompts[0].message.contains("register_webhook"));
    }

    #[test]
    fn mock_provisioner_validate_pending_steps() {
        let recipe = ProvisioningRecipe::new(RecipeId::new("val-test"), "1", "Validation test")
            .with_step(ProvisioningStep::new(
                StepId::new("s1"),
                ProvisioningStepType::PromptUser {
                    message: "Hi".to_string(),
                },
            ));
        let provisioner = MockProvisioner::new(recipe);
        let validation = provisioner.validate();
        assert!(!validation.valid);
        assert_eq!(validation.errors.len(), 1);
        assert!(validation.errors[0].contains("1 steps still pending"));
    }

    #[test]
    fn mock_provisioner_blocks_out_of_order_steps_until_dependencies_complete() {
        fcp_async_core::runtime::block_on_sync(async {
            let recipe = ProvisioningRecipe::new(
                RecipeId::new("dependency-test"),
                "1",
                "Dependency enforcement test",
            )
            .with_step(ProvisioningStep::new(
                StepId::new("ask_name"),
                ProvisioningStepType::PromptUser {
                    message: "Enter your name".to_string(),
                },
            ))
            .with_step(
                ProvisioningStep::new(
                    StepId::new("register_webhook"),
                    ProvisioningStepType::Webhook {
                        registration: WebhookRecipe {
                            registration_url: "https://api.example.test/webhooks".to_string(),
                            events: vec!["message.create".to_string()],
                            verification: WebhookVerification::ChallengeResponse {
                                challenge_param: "challenge".to_string(),
                            },
                            retry_policy: RetryConfig::default(),
                        },
                    },
                )
                .depends_on(StepId::new("ask_name")),
            );

            let mut provisioner = MockProvisioner::new(recipe);
            let error = provisioner
                .execute_step(StepId::new("register_webhook"))
                .await
                .expect_err("out-of-order execution should be blocked");
            let FcpError::Conflict { message } = error else {
                panic!("expected dependency conflict");
            };
            assert!(message.contains("ask_name"));
            assert_eq!(provisioner.step_logs.len(), 1);
            assert_eq!(provisioner.step_logs[0]["outcome"], "blocked_dependency");
            assert_eq!(
                provisioner.step_logs[0]["recovery_hint"],
                "Complete prerequisite steps first: ask_name"
            );

            let prompt = provisioner
                .execute_step(StepId::new("ask_name"))
                .await
                .expect("dependency step should execute");
            assert!(matches!(
                prompt,
                ProvisioningStepResult::AwaitingHuman { .. }
            ));
            provisioner.set_prompt_value("ask_name", "Emerald Elm");

            let completion = provisioner
                .execute_step(StepId::new("register_webhook"))
                .await
                .expect("dependent step should succeed after prerequisite completion");
            assert!(matches!(
                completion,
                ProvisioningStepResult::Completed { .. }
            ));
            assert_eq!(provisioner.webhook_registrations.len(), 1);
        })
        .expect("runtime should enforce provisioning dependencies");
    }

    #[test]
    fn mock_provisioner_step_logs_track_outcomes() {
        fcp_async_core::runtime::block_on_sync(async {
            let recipe = ProvisioningRecipe::new(RecipeId::new("log-test"), "1", "Log test")
                .with_step(ProvisioningStep::new(
                    StepId::new("oauth"),
                    ProvisioningStepType::Oauth {
                        flow: OAuthRecipe::ClientCredentials {
                            token_url: "https://auth.test/token".to_string(),
                            scopes: Vec::new(),
                        },
                    },
                ));
            let mut provisioner = MockProvisioner::new(recipe);
            provisioner
                .execute_step(StepId::new("oauth"))
                .await
                .unwrap();
            assert_eq!(provisioner.step_logs.len(), 1);
            assert_eq!(provisioner.step_logs[0]["outcome"], "completed");
            assert_eq!(provisioner.step_logs[0]["step_name"], "oauth");
            assert_eq!(provisioner.step_logs[0]["recipe_id"], "log-test");
            assert!(
                provisioner.step_logs[0]["duration_ms"].as_u64().is_some(),
                "step logs should include duration_ms"
            );
            assert!(
                provisioner.step_logs[0]["logged_at"].as_str().is_some(),
                "step logs should include a timestamp"
            );
        })
        .expect("runtime should execute step log test");
    }

    #[test]
    fn mock_provisioner_webhook_stores_registration_info() {
        fcp_async_core::runtime::block_on_sync(async {
            let recipe = ProvisioningRecipe::new(RecipeId::new("wh-test"), "1", "Webhook test")
                .with_step(ProvisioningStep::new(
                    StepId::new("wh1"),
                    ProvisioningStepType::Webhook {
                        registration: WebhookRecipe {
                            registration_url: "https://api.test/hooks".to_string(),
                            events: vec!["push".to_string(), "pr".to_string()],
                            verification: WebhookVerification::HmacSignature {
                                algorithm: "sha256".to_string(),
                                header: "X-Sig".to_string(),
                            },
                            retry_policy: RetryConfig::default(),
                        },
                    },
                ))
                .with_step(ProvisioningStep::new(
                    StepId::new("wh2"),
                    ProvisioningStepType::Webhook {
                        registration: WebhookRecipe {
                            registration_url: "https://api2.test/hooks".to_string(),
                            events: vec!["issue".to_string()],
                            verification: WebhookVerification::ChallengeResponse {
                                challenge_param: "c".to_string(),
                            },
                            retry_policy: RetryConfig::default(),
                        },
                    },
                ));
            let mut provisioner = MockProvisioner::new(recipe);
            provisioner.execute_step(StepId::new("wh1")).await.unwrap();
            provisioner.execute_step(StepId::new("wh2")).await.unwrap();
            assert_eq!(provisioner.webhook_registrations.len(), 2);
            assert_eq!(provisioner.webhook_registrations[0].1.len(), 2);
            assert_eq!(provisioner.webhook_registrations[1].1.len(), 1);
        })
        .expect("runtime should execute webhook registration test");
    }
}
