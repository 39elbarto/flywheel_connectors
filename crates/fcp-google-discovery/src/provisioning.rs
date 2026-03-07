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
                    "selected_escalations": { "type": "array", "items": { "type": "string" } },
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
}
