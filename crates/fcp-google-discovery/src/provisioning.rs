//! Google provisioning recipe planning derived from the policy catalog.
//!
//! This module bridges the Google provisioning policy baseline into concrete
//! FCP provisioning artifacts so connectors and hosts can expose setup flows
//! without re-encoding scope posture, escalation, or runtime-auth rules.

use std::collections::BTreeSet;

use fcp_core::{
    HumanPrompt, HumanPromptType, OAuthRecipe, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, SetupDescriptor, StepId,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{
    DEFAULT_GOOGLE_OAUTH_TOKEN_URL, GoogleAuthSourceDisposition, google_auth_source_policies,
};
use crate::policy::{
    GoogleGcloudAutomationBoundary, GooglePolicyCatalog, GoogleProvisioningScopeEscalation,
    GoogleProvisioningSurfacePolicy, PolicyCatalogError,
};

const GOOGLE_AUTHORIZATION_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_DEVICE_AUTHORIZATION_URL: &str = "https://oauth2.googleapis.com/device/code";
const DEFAULT_PROVISIONING_RECIPE_VERSION: &str = "1";
const DEFAULT_CALLBACK_PORT: u16 = 8765;
#[cfg(test)]
const DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECONDS: u64 = 5;
const DEFAULT_ESTIMATED_DURATION_MS: u64 = 180_000;
const WORKSPACE_EVENTS_ESTIMATED_DURATION_MS: u64 = 300_000;

/// Errors emitted while building Google provisioning bundles.
#[derive(Debug, thiserror::Error)]
pub enum GoogleProvisioningError {
    /// Embedded/default policy catalog could not be loaded.
    #[error(transparent)]
    Catalog(#[from] PolicyCatalogError),

    /// Requested provisioning surface is unknown.
    #[error("unknown google provisioning surface `{surface_id}`")]
    UnknownSurface {
        /// Requested surface identifier.
        surface_id: String,
    },

    /// Requested escalation trigger is not declared for the surface.
    #[error(
        "unknown google provisioning escalation trigger `{trigger}` for surface `{surface_id}`"
    )]
    UnknownEscalationTrigger {
        /// Surface identifier.
        surface_id: String,
        /// Rejected trigger.
        trigger: String,
    },
}

/// OAuth flow selection for Google setup.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GoogleProvisioningAuthFlow {
    /// Browser-driven authorization code flow with PKCE.
    AuthorizationCodePkce {
        /// Whether to auto-open the consent URL in a browser.
        auto_browser: bool,
        /// Local callback port used by the host during consent completion.
        callback_port: u16,
    },
    /// Headless/device-code flow.
    DeviceCode {
        /// Poll interval in seconds.
        poll_interval_seconds: u64,
    },
}

impl Default for GoogleProvisioningAuthFlow {
    fn default() -> Self {
        Self::AuthorizationCodePkce {
            auto_browser: true,
            callback_port: DEFAULT_CALLBACK_PORT,
        }
    }
}

/// Per-surface provisioning profile lifted out of the policy catalog.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleProvisioningSurfaceProfile {
    /// Stable surface identifier.
    pub surface_id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Narrow-by-default scope set.
    pub default_scopes: Vec<String>,
    /// Explicit escalation paths above the default scope set.
    pub escalation_paths: Vec<GoogleProvisioningScopeEscalation>,
}

impl GoogleProvisioningSurfaceProfile {
    /// Return the declared escalation trigger strings.
    #[must_use]
    pub fn escalation_triggers(&self) -> Vec<&str> {
        self.escalation_paths
            .iter()
            .map(|path| path.trigger.as_str())
            .collect()
    }

    /// Resolve the effective scope set for a chosen list of escalation triggers.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleProvisioningError::UnknownEscalationTrigger`] when any
    /// requested trigger is not declared for this surface.
    pub fn scopes_for_triggers<I, S>(
        &self,
        triggers: I,
    ) -> Result<Vec<String>, GoogleProvisioningError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut scopes = self
            .default_scopes
            .iter()
            .cloned()
            .collect::<BTreeSet<String>>();
        let mut seen_triggers = BTreeSet::new();

        for trigger in triggers {
            let trigger = trigger.as_ref().trim();
            if trigger.is_empty() || !seen_triggers.insert(trigger.to_string()) {
                continue;
            }

            let escalation = self
                .escalation_paths
                .iter()
                .find(|path| path.trigger == trigger)
                .ok_or_else(|| GoogleProvisioningError::UnknownEscalationTrigger {
                    surface_id: self.surface_id.clone(),
                    trigger: trigger.to_string(),
                })?;

            scopes.extend(escalation.add_scopes.iter().cloned());
        }

        Ok(scopes.into_iter().collect())
    }
}

impl From<&GoogleProvisioningSurfacePolicy> for GoogleProvisioningSurfaceProfile {
    fn from(value: &GoogleProvisioningSurfacePolicy) -> Self {
        Self {
            surface_id: value.surface_id.clone(),
            display_name: value.display_name.clone(),
            default_scopes: value.default_scopes.clone(),
            escalation_paths: value.escalation_paths.clone(),
        }
    }
}

/// Host/operator automation contract for one Google provisioning surface.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleProvisioningAutomationPlan {
    /// Selected OAuth flow for the provisioning UX.
    pub auth_flow: GoogleProvisioningAuthFlow,
    /// APIs that must be enabled before the connector is usable.
    pub required_api_enablement: Vec<String>,
    /// Additional project prerequisites that the host/operator must verify.
    pub project_prerequisites: Vec<String>,
    /// Consent restrictions that must be explained before escalation.
    pub consent_restriction_rules: Vec<String>,
    /// Separation rules between provisioning-time auth and runtime auth.
    pub runtime_separation_rules: Vec<String>,
    /// Allowed `gcloud` boundary for the entire Google surface.
    pub gcloud_boundary: GoogleGcloudAutomationBoundary,
    /// Bootstrap steps where `gcloud` meaningfully reduces friction.
    pub gcloud_assisted_steps: Vec<String>,
    /// Deterministic manual fallback steps.
    pub fallback_steps: Vec<String>,
    /// Required runtime-safe output produced by provisioning.
    pub runtime_materialization: Vec<String>,
    /// Auth source kinds allowed during provisioning.
    pub allowed_provisioning_auth_sources: Vec<String>,
    /// Auth source kinds allowed in steady-state runtime config.
    pub runtime_safe_auth_sources: Vec<String>,
}

/// Concrete Google provisioning bundle for one connector surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleProvisioningBundle {
    /// Policy catalog version.
    pub policy_version: String,
    /// Bead that produced the catalog revision.
    pub generated_from_bead: String,
    /// Top-level provisioning intent from the catalog.
    pub intent: String,
    /// Global narrow-by-default scope posture.
    pub default_scope_posture: String,
    /// Surface-specific provisioning profile.
    pub surface: GoogleProvisioningSurfaceProfile,
    /// Host/operator automation contract.
    pub automation: GoogleProvisioningAutomationPlan,
    /// Concrete FCP provisioning recipe.
    pub recipe: ProvisioningRecipe,
    /// Agent-visible setup descriptor.
    pub setup: SetupDescriptor,
}

impl GoogleProvisioningBundle {
    /// Resolve the effective scope set for selected escalation triggers.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleProvisioningError::UnknownEscalationTrigger`] when any
    /// trigger is not declared for the selected surface.
    pub fn scopes_for_triggers<I, S>(
        &self,
        triggers: I,
    ) -> Result<Vec<String>, GoogleProvisioningError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.surface.scopes_for_triggers(triggers)
    }
}

impl GooglePolicyCatalog {
    /// Build a provisioning bundle for a surface using the default auth flow.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleProvisioningError`] when the surface is unknown.
    pub fn provisioning_bundle(
        &self,
        surface_id: &str,
    ) -> Result<GoogleProvisioningBundle, GoogleProvisioningError> {
        self.provisioning_bundle_with_auth_flow(surface_id, GoogleProvisioningAuthFlow::default())
    }

    /// Build a provisioning bundle for a surface with an explicit auth flow.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleProvisioningError`] when the surface is unknown.
    pub fn provisioning_bundle_with_auth_flow(
        &self,
        surface_id: &str,
        auth_flow: GoogleProvisioningAuthFlow,
    ) -> Result<GoogleProvisioningBundle, GoogleProvisioningError> {
        let surface = self.provisioning_surface(surface_id).ok_or_else(|| {
            GoogleProvisioningError::UnknownSurface {
                surface_id: surface_id.to_string(),
            }
        })?;

        let surface_profile = GoogleProvisioningSurfaceProfile::from(surface);
        let automation = build_automation_plan(self, surface, auth_flow);
        let recipe = build_recipe(&surface_profile, &automation);
        let setup = build_setup_descriptor(self, &surface_profile, &automation);

        Ok(GoogleProvisioningBundle {
            policy_version: self.version.clone(),
            generated_from_bead: self.generated_from_bead.clone(),
            intent: self.provisioning_policy.intent.clone(),
            default_scope_posture: self.provisioning_policy.default_scope_posture.clone(),
            surface: surface_profile,
            automation,
            recipe,
            setup,
        })
    }
}

/// Load the embedded default policy catalog and build a provisioning bundle.
///
/// # Errors
///
/// Returns [`GoogleProvisioningError`] when the embedded catalog is invalid or
/// the requested surface is not present.
pub fn load_default_google_provisioning_bundle(
    surface_id: &str,
) -> Result<GoogleProvisioningBundle, GoogleProvisioningError> {
    GooglePolicyCatalog::load_default()?.provisioning_bundle(surface_id)
}

fn build_automation_plan(
    catalog: &GooglePolicyCatalog,
    surface: &GoogleProvisioningSurfacePolicy,
    auth_flow: GoogleProvisioningAuthFlow,
) -> GoogleProvisioningAutomationPlan {
    let (allowed_provisioning_auth_sources, runtime_safe_auth_sources) = auth_source_lists();

    GoogleProvisioningAutomationPlan {
        auth_flow,
        required_api_enablement: surface.required_api_enablement.clone(),
        project_prerequisites: surface.project_prerequisites.clone(),
        consent_restriction_rules: catalog
            .provisioning_policy
            .consent_restriction_rules
            .clone(),
        runtime_separation_rules: catalog.provisioning_policy.runtime_separation_rules.clone(),
        gcloud_boundary: catalog
            .provisioning_policy
            .gcloud_automation_boundary
            .clone(),
        gcloud_assisted_steps: surface.gcloud_assisted_steps.clone(),
        fallback_steps: surface.fallback_steps.clone(),
        runtime_materialization: surface.runtime_materialization.clone(),
        allowed_provisioning_auth_sources,
        runtime_safe_auth_sources,
    }
}

fn auth_source_lists() -> (Vec<String>, Vec<String>) {
    let provisioning = google_auth_source_policies()
        .iter()
        .filter(|policy| policy.provisioning == GoogleAuthSourceDisposition::Allowed)
        .map(|policy| policy.source.to_string())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();

    let runtime = google_auth_source_policies()
        .iter()
        .filter(|policy| policy.runtime == GoogleAuthSourceDisposition::Allowed)
        .map(|policy| policy.source.to_string())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();

    (provisioning, runtime)
}

fn build_recipe(
    surface: &GoogleProvisioningSurfaceProfile,
    automation: &GoogleProvisioningAutomationPlan,
) -> ProvisioningRecipe {
    let select_project = step_id(surface, "select_project");
    let review_scope_plan = step_id(surface, "review_scope_plan");
    let bootstrap_project_resources = step_id(surface, "bootstrap_project_resources");
    let authorize_connector = step_id(surface, "authorize_connector");
    let materialize_runtime_auth = step_id(surface, "materialize_runtime_auth");

    ProvisioningRecipe::new(
        RecipeId::new(format!("google/{}/setup", surface.surface_id)),
        DEFAULT_PROVISIONING_RECIPE_VERSION,
        format!("Provision {}", surface.display_name),
    )
    .with_step(ProvisioningStep::new(
        select_project.clone(),
        ProvisioningStepType::PromptUser {
            message: select_project_message(surface, automation),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            review_scope_plan.clone(),
            ProvisioningStepType::PromptUser {
                message: scope_review_message(surface),
            },
        )
        .with_approval(),
    )
    .with_step(
        ProvisioningStep::new(
            bootstrap_project_resources.clone(),
            ProvisioningStepType::PromptUser {
                message: bootstrap_message(surface, automation),
            },
        )
        .depends_on(select_project.clone())
        .with_approval(),
    )
    .with_step(
        ProvisioningStep::new(
            authorize_connector.clone(),
            ProvisioningStepType::Oauth {
                flow: oauth_recipe(&automation.auth_flow, &surface.default_scopes),
            },
        )
        .depends_on(select_project)
        .depends_on(review_scope_plan),
    )
    .with_step(
        ProvisioningStep::new(
            materialize_runtime_auth,
            ProvisioningStepType::PromptUser {
                message: runtime_materialization_message(surface, automation),
            },
        )
        .depends_on(bootstrap_project_resources)
        .depends_on(authorize_connector)
        .with_approval(),
    )
}

fn build_setup_descriptor(
    catalog: &GooglePolicyCatalog,
    surface: &GoogleProvisioningSurfaceProfile,
    automation: &GoogleProvisioningAutomationPlan,
) -> SetupDescriptor {
    let select_project = step_id(surface, "select_project");
    let review_scope_plan = step_id(surface, "review_scope_plan");
    let bootstrap_project_resources = step_id(surface, "bootstrap_project_resources");
    let authorize_connector = step_id(surface, "authorize_connector");
    let materialize_runtime_auth = step_id(surface, "materialize_runtime_auth");
    let escalation_summary = surface
        .escalation_paths
        .iter()
        .map(|path| json!({ "trigger": path.trigger, "add_scopes": path.add_scopes }))
        .collect::<Vec<_>>();

    SetupDescriptor {
        tool_descriptor: json!({
            "name": format!("fcp.google.{}.provision", surface.surface_id),
            "description": format!(
                "Provision {} with Google's narrow-by-default scope posture, explicit escalation triggers, and runtime-safe auth materialization.",
                surface.display_name
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_id": { "type": "string" },
                    "scope_triggers": { "type": "array", "items": { "type": "string" } },
                    "auth_flow": {
                        "type": "string",
                        "enum": ["authorization_code_pkce", "device_code"]
                    }
                },
                "additionalProperties": false
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "surface_id": { "type": "string" },
                    "default_scopes": { "type": "array", "items": { "type": "string" } },
                    "escalation_paths": { "type": "array", "items": { "type": "object" } },
                    "required_api_enablement": { "type": "array", "items": { "type": "string" } },
                    "runtime_safe_auth_sources": { "type": "array", "items": { "type": "string" } }
                },
                "required": [
                    "surface_id",
                    "default_scopes",
                    "escalation_paths",
                    "required_api_enablement",
                    "runtime_safe_auth_sources"
                ]
            },
            "metadata": {
                "policy_version": &catalog.version,
                "generated_from_bead": &catalog.generated_from_bead,
                "default_scope_posture": &catalog.provisioning_policy.default_scope_posture,
                "surface": surface,
                "escalation_paths": escalation_summary,
                "auth_flow": &automation.auth_flow,
                "required_api_enablement": &automation.required_api_enablement,
                "project_prerequisites": &automation.project_prerequisites,
                "consent_restriction_rules": &automation.consent_restriction_rules,
                "runtime_separation_rules": &automation.runtime_separation_rules,
                "gcloud_boundary": &automation.gcloud_boundary,
                "gcloud_assisted_steps": &automation.gcloud_assisted_steps,
                "fallback_steps": &automation.fallback_steps,
                "runtime_materialization": &automation.runtime_materialization,
                "allowed_provisioning_auth_sources": &automation.allowed_provisioning_auth_sources,
                "runtime_safe_auth_sources": &automation.runtime_safe_auth_sources
            }
        }),
        human_prompts: vec![
            HumanPrompt {
                step_id: select_project,
                prompt_type: HumanPromptType::Text,
                message: select_project_message(surface, automation),
                url: None,
            },
            HumanPrompt {
                step_id: review_scope_plan,
                prompt_type: HumanPromptType::Approval,
                message: scope_review_message(surface),
                url: None,
            },
            HumanPrompt {
                step_id: bootstrap_project_resources,
                prompt_type: HumanPromptType::Approval,
                message: bootstrap_message(surface, automation),
                url: None,
            },
            HumanPrompt {
                step_id: authorize_connector,
                prompt_type: HumanPromptType::Text,
                message: authorization_prompt_message(surface, automation),
                url: None,
            },
            HumanPrompt {
                step_id: materialize_runtime_auth,
                prompt_type: HumanPromptType::Approval,
                message: runtime_materialization_message(surface, automation),
                url: None,
            },
        ],
        estimated_duration_ms: Some(estimated_duration_ms(&surface.surface_id)),
    }
}

fn oauth_recipe(auth_flow: &GoogleProvisioningAuthFlow, scopes: &[String]) -> OAuthRecipe {
    match auth_flow {
        GoogleProvisioningAuthFlow::AuthorizationCodePkce {
            auto_browser,
            callback_port,
        } => OAuthRecipe::AuthorizationCodePkce {
            authorization_url: GOOGLE_AUTHORIZATION_URL.to_string(),
            token_url: DEFAULT_GOOGLE_OAUTH_TOKEN_URL.to_string(),
            scopes: scopes.to_vec(),
            auto_browser: *auto_browser,
            callback_port: *callback_port,
        },
        GoogleProvisioningAuthFlow::DeviceCode {
            poll_interval_seconds,
        } => OAuthRecipe::DeviceCode {
            device_authorization_url: GOOGLE_DEVICE_AUTHORIZATION_URL.to_string(),
            token_url: DEFAULT_GOOGLE_OAUTH_TOKEN_URL.to_string(),
            scopes: scopes.to_vec(),
            poll_interval_seconds: *poll_interval_seconds,
        },
    }
}

fn step_id(surface: &GoogleProvisioningSurfaceProfile, stage: &str) -> StepId {
    StepId::new(format!("google.{}.{}", surface.surface_id, stage))
}

fn select_project_message(
    surface: &GoogleProvisioningSurfaceProfile,
    automation: &GoogleProvisioningAutomationPlan,
) -> String {
    format!(
        "Select the Google Cloud project for {}. Enable APIs: {}. Prerequisites: {}.",
        surface.display_name,
        join_sentence_list(&automation.required_api_enablement),
        join_sentence_list(&automation.project_prerequisites),
    )
}

fn scope_review_message(surface: &GoogleProvisioningSurfaceProfile) -> String {
    format!(
        "Approve the default scope plan for {}. Default scopes: {}. Escalations stay opt-in: {}.",
        surface.display_name,
        join_sentence_list(&surface.default_scopes),
        escalation_summary(surface),
    )
}

fn bootstrap_message(
    surface: &GoogleProvisioningSurfaceProfile,
    automation: &GoogleProvisioningAutomationPlan,
) -> String {
    format!(
        "Approve project bootstrap for {}. gcloud-assisted steps: {}. Manual fallback: {}.",
        surface.display_name,
        join_sentence_list(&automation.gcloud_assisted_steps),
        join_sentence_list(&automation.fallback_steps),
    )
}

fn authorization_prompt_message(
    surface: &GoogleProvisioningSurfaceProfile,
    automation: &GoogleProvisioningAutomationPlan,
) -> String {
    match &automation.auth_flow {
        GoogleProvisioningAuthFlow::AuthorizationCodePkce {
            auto_browser,
            callback_port,
        } => format!(
            "Run Google OAuth authorization-code + PKCE for {} with scopes {}. auto_browser={} callback_port={}.",
            surface.display_name,
            join_sentence_list(&surface.default_scopes),
            auto_browser,
            callback_port,
        ),
        GoogleProvisioningAuthFlow::DeviceCode {
            poll_interval_seconds,
        } => format!(
            "Run Google device-code authorization for {} with scopes {}. poll_interval_seconds={}.",
            surface.display_name,
            join_sentence_list(&surface.default_scopes),
            poll_interval_seconds,
        ),
    }
}

fn runtime_materialization_message(
    surface: &GoogleProvisioningSurfaceProfile,
    automation: &GoogleProvisioningAutomationPlan,
) -> String {
    format!(
        "Confirm runtime-safe auth materialization for {}. Runtime outputs: {}. Runtime-safe auth sources: {}. Provisioning-only separation rules: {}.",
        surface.display_name,
        join_sentence_list(&automation.runtime_materialization),
        join_sentence_list(&automation.runtime_safe_auth_sources),
        join_sentence_list(&automation.runtime_separation_rules),
    )
}

fn estimated_duration_ms(surface_id: &str) -> u64 {
    if surface_id == "workspace_events" {
        WORKSPACE_EVENTS_ESTIMATED_DURATION_MS
    } else {
        DEFAULT_ESTIMATED_DURATION_MS
    }
}

fn escalation_summary(surface: &GoogleProvisioningSurfaceProfile) -> String {
    surface
        .escalation_paths
        .iter()
        .map(|path| {
            format!(
                "{} -> {}",
                path.trigger,
                join_sentence_list(&path.add_scopes)
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn join_sentence_list(items: &[String]) -> String {
    items.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_default_bundle_for_gmail_exposes_policy_and_recipe() {
        let bundle = load_default_google_provisioning_bundle("gmail")
            .expect("gmail bundle should load from embedded catalog");

        assert_eq!(bundle.policy_version, "2026-03-06");
        assert_eq!(
            bundle.generated_from_bead,
            "flywheel_connectors-lszk.45.1.8.1"
        );
        assert_eq!(bundle.surface.surface_id, "gmail");
        assert_eq!(
            bundle.surface.default_scopes,
            vec!["https://www.googleapis.com/auth/gmail.readonly".to_string()]
        );
        assert!(
            bundle
                .automation
                .required_api_enablement
                .contains(&"Gmail API".to_string())
        );
        assert_eq!(bundle.recipe.id.as_str(), "google/gmail/setup");
        assert_eq!(bundle.recipe.steps.len(), 5);
        assert_eq!(
            bundle.setup.tool_descriptor["name"],
            json!("fcp.google.gmail.provision")
        );
        assert_eq!(
            bundle.setup.estimated_duration_ms,
            Some(DEFAULT_ESTIMATED_DURATION_MS)
        );
    }

    #[test]
    fn provisioning_auth_source_lists_respect_runtime_separation() {
        let bundle = load_default_google_provisioning_bundle("calendar")
            .expect("calendar bundle should load from embedded catalog");

        assert_eq!(
            bundle.automation.allowed_provisioning_auth_sources,
            vec![
                "access_token".to_string(),
                "application_default_credentials".to_string(),
                "credential_id".to_string(),
                "credentials_file".to_string(),
                "default_credentials".to_string(),
                "oauth_refresh".to_string()
            ]
        );
        assert_eq!(
            bundle.automation.runtime_safe_auth_sources,
            vec![
                "access_token".to_string(),
                "credential_id".to_string(),
                "oauth_refresh".to_string()
            ]
        );
    }

    #[test]
    fn scopes_for_triggers_add_declared_escalations_once() {
        let bundle = load_default_google_provisioning_bundle("gmail")
            .expect("gmail bundle should load from embedded catalog");

        let scopes = bundle
            .scopes_for_triggers([
                "User enables outbound send or draft-send workflows.",
                "User enables outbound send or draft-send workflows.",
            ])
            .expect("known trigger should resolve");

        assert_eq!(
            scopes,
            vec![
                "https://www.googleapis.com/auth/gmail.compose".to_string(),
                "https://www.googleapis.com/auth/gmail.readonly".to_string(),
                "https://www.googleapis.com/auth/gmail.send".to_string()
            ]
        );
    }

    #[test]
    fn scopes_for_triggers_rejects_unknown_escalation() {
        let bundle = load_default_google_provisioning_bundle("calendar")
            .expect("calendar bundle should load from embedded catalog");

        let err = bundle
            .scopes_for_triggers(["definitely not a real trigger"])
            .expect_err("unknown trigger should fail closed");
        let message = err.to_string();
        assert!(message.contains("unknown google provisioning escalation trigger"));
        assert!(message.contains("calendar"));
    }

    #[test]
    fn workspace_events_bundle_carries_pubsub_bootstrap_guidance() {
        let bundle = load_default_google_provisioning_bundle("workspace_events")
            .expect("workspace events bundle should load from embedded catalog");

        assert_eq!(
            bundle.setup.estimated_duration_ms,
            Some(WORKSPACE_EVENTS_ESTIMATED_DURATION_MS)
        );
        assert!(
            bundle
                .automation
                .required_api_enablement
                .contains(&"Google Cloud Pub/Sub API".to_string())
        );
        assert!(
            bundle
                .automation
                .gcloud_assisted_steps
                .iter()
                .any(|step| step.contains("Pub/Sub topic"))
        );
        let bootstrap_step = bundle
            .recipe
            .steps
            .iter()
            .find(|step| step.id.as_str() == "google.workspace_events.bootstrap_project_resources")
            .expect("workspace events bundle should include bootstrap step");
        let ProvisioningStepType::PromptUser { message } = &bootstrap_step.kind else {
            panic!("bootstrap step should be a prompt-user step");
        };
        assert!(message.contains("Pub/Sub"));
    }

    #[test]
    fn bundle_with_device_code_auth_flow_uses_device_code_recipe() {
        let catalog = GooglePolicyCatalog::load_default().expect("embedded catalog should load");
        let bundle = catalog
            .provisioning_bundle_with_auth_flow(
                "calendar",
                GoogleProvisioningAuthFlow::DeviceCode {
                    poll_interval_seconds: DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECONDS,
                },
            )
            .expect("calendar bundle should build");

        let oauth_step = bundle
            .recipe
            .steps
            .iter()
            .find(|step| step.id.as_str() == "google.calendar.authorize_connector")
            .expect("authorization step should exist");
        let ProvisioningStepType::Oauth { flow } = &oauth_step.kind else {
            panic!("authorization step should be oauth");
        };
        let OAuthRecipe::DeviceCode {
            device_authorization_url,
            token_url,
            scopes,
            poll_interval_seconds,
        } = flow
        else {
            panic!("device-code flow should be selected");
        };
        assert_eq!(device_authorization_url, GOOGLE_DEVICE_AUTHORIZATION_URL);
        assert_eq!(token_url, DEFAULT_GOOGLE_OAUTH_TOKEN_URL);
        assert_eq!(
            scopes,
            &vec!["https://www.googleapis.com/auth/calendar.readonly".to_string()]
        );
        assert_eq!(
            *poll_interval_seconds,
            DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECONDS
        );
        assert_eq!(
            bundle.setup.tool_descriptor["metadata"]["auth_flow"],
            json!(GoogleProvisioningAuthFlow::DeviceCode {
                poll_interval_seconds: DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECONDS,
            })
        );
    }

    // ── GoogleProvisioningAuthFlow tests ──────────────────────────────

    #[test]
    fn auth_flow_default_is_authorization_code_pkce() {
        let flow = GoogleProvisioningAuthFlow::default();
        match flow {
            GoogleProvisioningAuthFlow::AuthorizationCodePkce {
                auto_browser,
                callback_port,
            } => {
                assert!(auto_browser);
                assert_eq!(callback_port, DEFAULT_CALLBACK_PORT);
            }
            GoogleProvisioningAuthFlow::DeviceCode { .. } => {
                panic!("expected AuthorizationCodePkce, got DeviceCode")
            }
        }
    }

    #[test]
    fn auth_flow_serde_roundtrip_authorization_code_pkce() {
        let flow = GoogleProvisioningAuthFlow::AuthorizationCodePkce {
            auto_browser: false,
            callback_port: 9999,
        };
        let serialized = serde_json::to_string(&flow).expect("serialize");
        let deserialized: GoogleProvisioningAuthFlow =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(flow, deserialized);
    }

    #[test]
    fn auth_flow_serde_roundtrip_device_code() {
        let flow = GoogleProvisioningAuthFlow::DeviceCode {
            poll_interval_seconds: 10,
        };
        let serialized = serde_json::to_string(&flow).expect("serialize");
        let deserialized: GoogleProvisioningAuthFlow =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(flow, deserialized);
    }

    #[test]
    fn auth_flow_clone_and_eq() {
        let a = GoogleProvisioningAuthFlow::default();
        let b = a.clone();
        assert_eq!(a, b);

        let c = GoogleProvisioningAuthFlow::DeviceCode {
            poll_interval_seconds: 5,
        };
        assert_ne!(a, c);
    }

    #[test]
    fn auth_flow_debug_format() {
        let flow = GoogleProvisioningAuthFlow::default();
        let debug = format!("{flow:?}");
        assert!(debug.contains("AuthorizationCodePkce"), "got: {debug}");
    }

    // ── GoogleProvisioningError tests ─────────────────────────────────

    #[test]
    fn error_unknown_surface_display() {
        let err = GoogleProvisioningError::UnknownSurface {
            surface_id: "nonexistent".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("unknown google provisioning surface"),
            "got: {msg}"
        );
        assert!(msg.contains("nonexistent"), "got: {msg}");
    }

    #[test]
    fn error_unknown_escalation_trigger_display() {
        let err = GoogleProvisioningError::UnknownEscalationTrigger {
            surface_id: "gmail".to_string(),
            trigger: "bad-trigger".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("unknown google provisioning escalation trigger"),
            "got: {msg}"
        );
        assert!(msg.contains("bad-trigger"), "got: {msg}");
        assert!(msg.contains("gmail"), "got: {msg}");
    }

    #[test]
    fn error_catalog_variant_is_transparent() {
        let catalog_err = PolicyCatalogError::Invalid {
            message: "test catalog error".to_string(),
        };
        let err = GoogleProvisioningError::from(catalog_err);
        let msg = err.to_string();
        assert!(msg.contains("test catalog error"), "got: {msg}");
    }

    // ── GoogleProvisioningSurfaceProfile tests ────────────────────────

    #[test]
    fn surface_profile_escalation_triggers_returns_all_triggers() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let triggers = bundle.surface.escalation_triggers();
        assert!(
            !triggers.is_empty(),
            "gmail should have at least one escalation trigger"
        );
        for trigger in &triggers {
            assert!(!trigger.is_empty(), "trigger should not be empty");
        }
    }

    #[test]
    fn surface_profile_scopes_for_empty_triggers_returns_defaults() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let scopes = bundle
            .surface
            .scopes_for_triggers(Vec::<&str>::new())
            .expect("empty triggers should succeed");
        assert_eq!(scopes, bundle.surface.default_scopes);
    }

    #[test]
    fn surface_profile_scopes_for_whitespace_only_triggers_returns_defaults() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let scopes = bundle
            .surface
            .scopes_for_triggers(["  ", "", "\t"])
            .expect("whitespace-only triggers should be ignored");
        assert_eq!(scopes, bundle.surface.default_scopes);
    }

    #[test]
    fn surface_profile_from_policy_preserves_fields() {
        let policy = GoogleProvisioningSurfacePolicy {
            surface_id: "test_surface".to_string(),
            display_name: "Test Surface".to_string(),
            default_scopes: vec!["scope.a".to_string(), "scope.b".to_string()],
            escalation_paths: vec![GoogleProvisioningScopeEscalation {
                trigger: "test trigger".to_string(),
                add_scopes: vec!["scope.c".to_string()],
                notes: vec![],
            }],
            required_api_enablement: vec!["Test API".to_string()],
            project_prerequisites: vec!["prereq".to_string()],
            gcloud_assisted_steps: vec!["step1".to_string()],
            fallback_steps: vec!["fallback1".to_string()],
            runtime_materialization: vec!["output1".to_string()],
            notes: vec![],
        };
        let profile = GoogleProvisioningSurfaceProfile::from(&policy);
        assert_eq!(profile.surface_id, "test_surface");
        assert_eq!(profile.display_name, "Test Surface");
        assert_eq!(profile.default_scopes.len(), 2);
        assert_eq!(profile.escalation_paths.len(), 1);
        assert_eq!(profile.escalation_triggers(), vec!["test trigger"]);
    }

    #[test]
    fn surface_profile_serde_roundtrip() {
        let profile = GoogleProvisioningSurfaceProfile {
            surface_id: "calendar".to_string(),
            display_name: "Google Calendar".to_string(),
            default_scopes: vec!["scope.readonly".to_string()],
            escalation_paths: vec![],
        };
        let serialized = serde_json::to_string(&profile).expect("serialize");
        let deserialized: GoogleProvisioningSurfaceProfile =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(profile, deserialized);
    }

    #[test]
    fn surface_profile_clone_and_eq() {
        let profile = GoogleProvisioningSurfaceProfile {
            surface_id: "test".to_string(),
            display_name: "Test".to_string(),
            default_scopes: vec!["s1".to_string()],
            escalation_paths: vec![],
        };
        let cloned = profile.clone();
        assert_eq!(profile, cloned);
    }

    // ── GoogleProvisioningAutomationPlan tests ───────────────────────

    #[test]
    fn automation_plan_serde_roundtrip() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let serialized = serde_json::to_string(&bundle.automation).expect("serialize");
        let deserialized: GoogleProvisioningAutomationPlan =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(bundle.automation, deserialized);
    }

    #[test]
    fn automation_plan_contains_auth_source_lists() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        assert!(
            !bundle
                .automation
                .allowed_provisioning_auth_sources
                .is_empty(),
            "provisioning auth sources should not be empty"
        );
        assert!(
            !bundle.automation.runtime_safe_auth_sources.is_empty(),
            "runtime auth sources should not be empty"
        );
        // Runtime set should be a subset of provisioning set
        for source in &bundle.automation.runtime_safe_auth_sources {
            assert!(
                bundle
                    .automation
                    .allowed_provisioning_auth_sources
                    .contains(source),
                "runtime source {source} should also be in provisioning set"
            );
        }
    }

    #[test]
    fn automation_plan_gcloud_boundary_is_populated() {
        let bundle = load_default_google_provisioning_bundle("calendar")
            .expect("calendar bundle should load");
        let boundary_debug = format!("{:?}", bundle.automation.gcloud_boundary);
        assert!(
            !boundary_debug.is_empty(),
            "gcloud boundary should be populated"
        );
    }

    // ── GoogleProvisioningBundle tests ────────────────────────────────

    #[test]
    fn bundle_scopes_for_triggers_delegates_to_surface() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let from_bundle = bundle
            .scopes_for_triggers(Vec::<&str>::new())
            .expect("bundle delegation should work");
        let from_surface = bundle
            .surface
            .scopes_for_triggers(Vec::<&str>::new())
            .expect("surface direct should work");
        assert_eq!(from_bundle, from_surface);
    }

    #[test]
    fn bundle_serde_roundtrip() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let serialized = serde_json::to_string(&bundle).expect("serialize");
        let deserialized: GoogleProvisioningBundle =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(deserialized.policy_version, bundle.policy_version);
        assert_eq!(deserialized.surface.surface_id, bundle.surface.surface_id);
        assert_eq!(deserialized.recipe.id.as_str(), bundle.recipe.id.as_str());
    }

    #[test]
    fn bundle_for_unknown_surface_returns_error() {
        let err = load_default_google_provisioning_bundle("nonexistent_surface")
            .expect_err("unknown surface should fail");
        assert!(
            matches!(err, GoogleProvisioningError::UnknownSurface { .. }),
            "unexpected error: {err}"
        );
    }

    // ── Recipe structure tests ───────────────────────────────────────

    #[test]
    fn recipe_has_five_steps_for_all_surfaces() {
        for surface_id in &[
            "gmail",
            "calendar",
            "admin_reports",
            "people",
            "workspace_events",
        ] {
            let bundle = load_default_google_provisioning_bundle(surface_id)
                .unwrap_or_else(|err| panic!("{surface_id} bundle should load: {err}"));
            assert_eq!(
                bundle.recipe.steps.len(),
                5,
                "{surface_id} recipe should have 5 steps"
            );
        }
    }

    #[test]
    fn recipe_step_ids_follow_naming_convention() {
        let bundle = load_default_google_provisioning_bundle("calendar")
            .expect("calendar bundle should load");
        let expected_suffixes = [
            "select_project",
            "review_scope_plan",
            "bootstrap_project_resources",
            "authorize_connector",
            "materialize_runtime_auth",
        ];
        for suffix in expected_suffixes {
            let expected_id = format!("google.calendar.{suffix}");
            assert!(
                bundle
                    .recipe
                    .steps
                    .iter()
                    .any(|step| step.id.as_str() == expected_id),
                "recipe should contain step {expected_id}"
            );
        }
    }

    #[test]
    fn recipe_authorize_step_uses_authorization_code_pkce_by_default() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let oauth_step = bundle
            .recipe
            .steps
            .iter()
            .find(|step| step.id.as_str() == "google.gmail.authorize_connector")
            .expect("authorization step should exist");
        let ProvisioningStepType::Oauth { flow } = &oauth_step.kind else {
            panic!("authorization step should be oauth");
        };
        match flow {
            OAuthRecipe::AuthorizationCodePkce {
                authorization_url,
                token_url,
                ..
            } => {
                assert_eq!(authorization_url, GOOGLE_AUTHORIZATION_URL);
                assert_eq!(token_url, DEFAULT_GOOGLE_OAUTH_TOKEN_URL);
            }
            other => panic!("expected AuthorizationCodePkce, got {other:?}"),
        }
    }

    #[test]
    fn recipe_id_follows_surface_naming() {
        let bundle = load_default_google_provisioning_bundle("calendar")
            .expect("calendar bundle should load");
        assert_eq!(bundle.recipe.id.as_str(), "google/calendar/setup");
    }

    // ── Setup descriptor tests ──────────────────────────────────────

    #[test]
    fn setup_descriptor_has_five_human_prompts() {
        for surface_id in &[
            "gmail",
            "calendar",
            "admin_reports",
            "people",
            "workspace_events",
        ] {
            let bundle = load_default_google_provisioning_bundle(surface_id)
                .unwrap_or_else(|err| panic!("{surface_id} bundle should load: {err}"));
            assert_eq!(
                bundle.setup.human_prompts.len(),
                5,
                "{surface_id} setup should have 5 human prompts"
            );
        }
    }

    #[test]
    fn setup_descriptor_prompt_types_are_correct() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let types: Vec<_> = bundle
            .setup
            .human_prompts
            .iter()
            .map(|p| &p.prompt_type)
            .collect();
        assert_eq!(*types[0], HumanPromptType::Text); // select_project
        assert_eq!(*types[1], HumanPromptType::Approval); // review_scope_plan
        assert_eq!(*types[2], HumanPromptType::Approval); // bootstrap_project_resources
        assert_eq!(*types[3], HumanPromptType::Text); // authorize_connector
        assert_eq!(*types[4], HumanPromptType::Approval); // materialize_runtime_auth
    }

    #[test]
    fn setup_descriptor_tool_descriptor_contains_required_schema_fields() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let td = &bundle.setup.tool_descriptor;
        assert!(td.get("name").is_some(), "tool descriptor should have name");
        assert!(
            td.get("description").is_some(),
            "tool descriptor should have description"
        );
        assert!(
            td.get("input_schema").is_some(),
            "tool descriptor should have input_schema"
        );
        assert!(
            td.get("output_schema").is_some(),
            "tool descriptor should have output_schema"
        );
        assert!(
            td.get("metadata").is_some(),
            "tool descriptor should have metadata"
        );
        assert!(
            td["input_schema"]["properties"]
                .get("scope_triggers")
                .is_some(),
            "tool descriptor should expose scope_triggers in the input schema"
        );
        assert!(
            td["input_schema"]["properties"]
                .get("selected_escalations")
                .is_none(),
            "tool descriptor should not expose the stale selected_escalations field"
        );
    }

    #[test]
    fn setup_descriptor_metadata_contains_policy_and_surface_info() {
        let bundle = load_default_google_provisioning_bundle("calendar")
            .expect("calendar bundle should load");
        let metadata = &bundle.setup.tool_descriptor["metadata"];
        assert!(
            metadata.get("policy_version").is_some(),
            "metadata should have policy_version"
        );
        assert!(
            metadata.get("surface").is_some(),
            "metadata should have surface"
        );
        assert!(
            metadata.get("escalation_paths").is_some(),
            "metadata should have escalation_paths"
        );
        assert!(
            metadata.get("auth_flow").is_some(),
            "metadata should have auth_flow"
        );
        assert!(
            metadata.get("required_api_enablement").is_some(),
            "metadata should have required_api_enablement"
        );
        assert!(
            metadata.get("gcloud_boundary").is_some(),
            "metadata should have gcloud_boundary"
        );
    }

    // ── Estimated duration tests ────────────────────────────────────

    #[test]
    fn estimated_duration_workspace_events_is_longer() {
        let ws_duration = estimated_duration_ms("workspace_events");
        let default_duration = estimated_duration_ms("gmail");
        assert_eq!(ws_duration, WORKSPACE_EVENTS_ESTIMATED_DURATION_MS);
        assert!(
            ws_duration > default_duration,
            "workspace events ({ws_duration}) should have longer duration than default ({default_duration})"
        );
    }

    #[test]
    fn estimated_duration_default_for_generic_surface() {
        assert_eq!(
            estimated_duration_ms("gmail"),
            DEFAULT_ESTIMATED_DURATION_MS
        );
        assert_eq!(
            estimated_duration_ms("calendar"),
            DEFAULT_ESTIMATED_DURATION_MS
        );
        assert_eq!(
            estimated_duration_ms("unknown"),
            DEFAULT_ESTIMATED_DURATION_MS
        );
    }

    // ── Helper function tests ───────────────────────────────────────

    #[test]
    fn join_sentence_list_empty() {
        assert_eq!(join_sentence_list(&[]), "");
    }

    #[test]
    fn join_sentence_list_single_item() {
        let items = vec!["hello".to_string()];
        assert_eq!(join_sentence_list(&items), "hello");
    }

    #[test]
    fn join_sentence_list_multiple_items() {
        let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(join_sentence_list(&items), "a; b; c");
    }

    #[test]
    fn escalation_summary_format() {
        let profile = GoogleProvisioningSurfaceProfile {
            surface_id: "test".to_string(),
            display_name: "Test".to_string(),
            default_scopes: vec!["scope.a".to_string()],
            escalation_paths: vec![
                GoogleProvisioningScopeEscalation {
                    trigger: "trigger1".to_string(),
                    add_scopes: vec!["scope.b".to_string()],
                    notes: vec![],
                },
                GoogleProvisioningScopeEscalation {
                    trigger: "trigger2".to_string(),
                    add_scopes: vec!["scope.c".to_string(), "scope.d".to_string()],
                    notes: vec![],
                },
            ],
        };
        let summary = escalation_summary(&profile);
        assert!(summary.contains("trigger1"), "got: {summary}");
        assert!(summary.contains("trigger2"), "got: {summary}");
        assert!(summary.contains("scope.b"), "got: {summary}");
        assert!(summary.contains(" | "), "got: {summary}");
    }

    #[test]
    fn escalation_summary_empty_paths() {
        let profile = GoogleProvisioningSurfaceProfile {
            surface_id: "test".to_string(),
            display_name: "Test".to_string(),
            default_scopes: vec![],
            escalation_paths: vec![],
        };
        let summary = escalation_summary(&profile);
        assert_eq!(summary, "");
    }

    // ── oauth_recipe tests ──────────────────────────────────────────

    #[test]
    fn oauth_recipe_authorization_code_pkce_structure() {
        let scopes = vec!["scope.a".to_string(), "scope.b".to_string()];
        let flow = GoogleProvisioningAuthFlow::AuthorizationCodePkce {
            auto_browser: false,
            callback_port: 12345,
        };
        let recipe = oauth_recipe(&flow, &scopes);
        match recipe {
            OAuthRecipe::AuthorizationCodePkce {
                authorization_url,
                token_url,
                scopes: recipe_scopes,
                auto_browser,
                callback_port,
            } => {
                assert_eq!(authorization_url, GOOGLE_AUTHORIZATION_URL);
                assert_eq!(token_url, DEFAULT_GOOGLE_OAUTH_TOKEN_URL);
                assert_eq!(recipe_scopes, scopes);
                assert!(!auto_browser);
                assert_eq!(callback_port, 12345);
            }
            other => panic!("expected AuthorizationCodePkce, got {other:?}"),
        }
    }

    #[test]
    fn oauth_recipe_device_code_structure() {
        let scopes = vec!["scope.x".to_string()];
        let flow = GoogleProvisioningAuthFlow::DeviceCode {
            poll_interval_seconds: 7,
        };
        let recipe = oauth_recipe(&flow, &scopes);
        match recipe {
            OAuthRecipe::DeviceCode {
                device_authorization_url,
                token_url,
                scopes: recipe_scopes,
                poll_interval_seconds,
            } => {
                assert_eq!(device_authorization_url, GOOGLE_DEVICE_AUTHORIZATION_URL);
                assert_eq!(token_url, DEFAULT_GOOGLE_OAUTH_TOKEN_URL);
                assert_eq!(recipe_scopes, scopes);
                assert_eq!(poll_interval_seconds, 7);
            }
            other => panic!("expected DeviceCode, got {other:?}"),
        }
    }

    // ── Cross-surface consistency tests ─────────────────────────────

    #[test]
    fn all_surfaces_produce_valid_bundles() {
        let catalog = GooglePolicyCatalog::load_default().expect("embedded catalog should load");
        for surface in &catalog.provisioning_policy.surfaces {
            let bundle = catalog
                .provisioning_bundle(&surface.surface_id)
                .unwrap_or_else(|err| panic!("{} bundle should build: {err}", surface.surface_id));
            assert_eq!(bundle.surface.surface_id, surface.surface_id);
            assert_eq!(bundle.recipe.steps.len(), 5);
            assert_eq!(bundle.setup.human_prompts.len(), 5);
            assert!(
                bundle.setup.estimated_duration_ms.is_some(),
                "{} should have estimated duration",
                surface.surface_id
            );
        }
    }

    #[test]
    fn all_surfaces_have_consistent_recipe_and_setup_step_ids() {
        let catalog = GooglePolicyCatalog::load_default().expect("embedded catalog should load");
        for surface in &catalog.provisioning_policy.surfaces {
            let bundle = catalog
                .provisioning_bundle(&surface.surface_id)
                .expect("bundle should build");
            let recipe_ids: BTreeSet<_> = bundle
                .recipe
                .steps
                .iter()
                .map(|s| s.id.as_str().to_string())
                .collect();
            let prompt_ids: BTreeSet<_> = bundle
                .setup
                .human_prompts
                .iter()
                .map(|p| p.step_id.as_str().to_string())
                .collect();
            assert_eq!(
                recipe_ids, prompt_ids,
                "{}: recipe step ids should match human prompt step ids",
                surface.surface_id
            );
        }
    }

    #[test]
    fn calendar_bundle_has_correct_surface_metadata() {
        let bundle = load_default_google_provisioning_bundle("calendar")
            .expect("calendar bundle should load");
        assert!(
            bundle.surface.display_name.contains("Calendar"),
            "display name should mention Calendar: {}",
            bundle.surface.display_name
        );
        assert!(
            bundle
                .surface
                .default_scopes
                .iter()
                .any(|s| s.contains("calendar")),
            "calendar should have calendar-related scopes"
        );
    }

    #[test]
    fn people_bundle_has_explicit_contact_directory_scope_posture() {
        let bundle =
            load_default_google_provisioning_bundle("people").expect("people bundle should load");
        assert_eq!(bundle.surface.surface_id, "people");
        assert_eq!(
            bundle.surface.default_scopes,
            vec!["https://www.googleapis.com/auth/contacts.readonly".to_string()]
        );
        assert!(
            bundle
                .surface
                .escalation_paths
                .iter()
                .any(|path| path.trigger.contains("directory search"))
        );
        assert!(
            bundle
                .surface
                .escalation_paths
                .iter()
                .flat_map(|path| path.add_scopes.iter())
                .any(|scope| scope == "https://www.googleapis.com/auth/directory.readonly")
        );
    }

    #[test]
    fn admin_reports_bundle_keeps_audit_default_and_usage_escalation() {
        let bundle = load_default_google_provisioning_bundle("admin_reports")
            .expect("admin_reports bundle should load");
        assert_eq!(bundle.surface.surface_id, "admin_reports");
        assert_eq!(
            bundle.surface.default_scopes,
            vec!["https://www.googleapis.com/auth/admin.reports.audit.readonly".to_string()]
        );
        assert!(
            bundle
                .surface
                .escalation_paths
                .iter()
                .any(|path| path.trigger.contains("usage-report workflows"))
        );
        assert!(
            bundle
                .surface
                .escalation_paths
                .iter()
                .flat_map(|path| path.add_scopes.iter())
                .any(
                    |scope| scope == "https://www.googleapis.com/auth/admin.reports.usage.readonly"
                )
        );
    }

    // ── Message content tests ───────────────────────────────────────

    #[test]
    fn select_project_message_contains_surface_and_apis() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let select_step = bundle
            .recipe
            .steps
            .iter()
            .find(|s| s.id.as_str() == "google.gmail.select_project")
            .expect("select_project step should exist");
        let ProvisioningStepType::PromptUser { message } = &select_step.kind else {
            panic!("select_project should be PromptUser");
        };
        assert!(
            message.contains("Gmail"),
            "message should mention surface: {message}"
        );
        assert!(
            message.contains("Gmail API"),
            "message should mention required API: {message}"
        );
    }

    #[test]
    fn scope_review_message_contains_default_scopes() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let review_step = bundle
            .recipe
            .steps
            .iter()
            .find(|s| s.id.as_str() == "google.gmail.review_scope_plan")
            .expect("review_scope_plan step should exist");
        let ProvisioningStepType::PromptUser { message } = &review_step.kind else {
            panic!("review_scope_plan should be PromptUser");
        };
        assert!(
            message.contains("gmail.readonly"),
            "message should contain default scope: {message}"
        );
    }

    #[test]
    fn authorization_prompt_mentions_scopes_and_flow() {
        let bundle = load_default_google_provisioning_bundle("calendar")
            .expect("calendar bundle should load");
        let auth_step = bundle
            .recipe
            .steps
            .iter()
            .find(|s| s.id.as_str() == "google.calendar.authorize_connector")
            .expect("authorize_connector step should exist");
        // The authorization step is OAuth type, not PromptUser
        assert!(
            matches!(&auth_step.kind, ProvisioningStepType::Oauth { .. }),
            "authorize step should be OAuth type"
        );
        // But the setup descriptor prompt for authorize should contain flow info
        let auth_prompt = bundle
            .setup
            .human_prompts
            .iter()
            .find(|p| p.step_id.as_str() == "google.calendar.authorize_connector")
            .expect("authorize prompt should exist");
        assert!(
            auth_prompt.message.contains("calendar"),
            "auth prompt should mention surface: {}",
            auth_prompt.message
        );
    }

    #[test]
    fn runtime_materialization_message_mentions_runtime_safe_sources() {
        let bundle =
            load_default_google_provisioning_bundle("gmail").expect("gmail bundle should load");
        let materialize_step = bundle
            .recipe
            .steps
            .iter()
            .find(|s| s.id.as_str() == "google.gmail.materialize_runtime_auth")
            .expect("materialize_runtime_auth step should exist");
        let ProvisioningStepType::PromptUser { message } = &materialize_step.kind else {
            panic!("materialize_runtime_auth should be PromptUser");
        };
        assert!(
            message.contains("runtime"),
            "message should mention runtime: {message}"
        );
    }

    // ── step_id helper tests ────────────────────────────────────────

    #[test]
    fn step_id_follows_google_surface_stage_format() {
        let profile = GoogleProvisioningSurfaceProfile {
            surface_id: "drive".to_string(),
            display_name: "Google Drive".to_string(),
            default_scopes: vec![],
            escalation_paths: vec![],
        };
        let id = step_id(&profile, "some_stage");
        assert_eq!(id.as_str(), "google.drive.some_stage");
    }

    // ── auth_source_lists tests ─────────────────────────────────────

    #[test]
    fn auth_source_lists_are_sorted_and_deduplicated() {
        let (provisioning, runtime) = auth_source_lists();
        let provisioning_sorted = {
            let mut sorted = provisioning.clone();
            sorted.sort();
            sorted.dedup();
            sorted
        };
        assert_eq!(
            provisioning, provisioning_sorted,
            "provisioning sources should be sorted and deduplicated"
        );
        let runtime_sorted = {
            let mut sorted = runtime.clone();
            sorted.sort();
            sorted.dedup();
            sorted
        };
        assert_eq!(
            runtime, runtime_sorted,
            "runtime sources should be sorted and deduplicated"
        );
    }

    #[test]
    fn auth_source_lists_provisioning_is_superset_of_runtime() {
        let (provisioning, runtime) = auth_source_lists();
        let prov_set: BTreeSet<_> = provisioning.iter().collect();
        for source in &runtime {
            assert!(
                prov_set.contains(source),
                "runtime source {source} missing from provisioning set"
            );
        }
    }
}
