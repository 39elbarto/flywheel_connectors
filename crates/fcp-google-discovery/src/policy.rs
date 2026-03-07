//! Google policy/capability mapping catalog for generator and migration workflows.
//!
//! This module provides a deterministic, machine-readable mapping from
//! Discovery service/method identifiers to FCP capability and safety metadata.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{DiscoveryError, ServiceAliasRegistry};

const DEFAULT_POLICY_MATRIX_JSON: &str = include_str!("../data/google_policy_matrix.v1.json");

/// Errors emitted while loading or validating the policy catalog.
#[derive(Debug, thiserror::Error)]
pub enum PolicyCatalogError {
    /// JSON parsing failed.
    #[error("failed to parse policy catalog JSON: {source}")]
    JsonDecode {
        /// Upstream JSON parser error.
        source: serde_json::Error,
    },

    /// Catalog-level validation failure.
    #[error("invalid policy catalog: {message}")]
    Invalid {
        /// Validation failure summary.
        message: String,
    },
}

/// Approval mode required for an operation class.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyApprovalMode {
    /// No explicit approval gate.
    None,
    /// Policy-driven approval decision.
    Policy,
    /// Interactive human approval required.
    Interactive,
    /// Elevation token required.
    ElevationToken,
}

/// Risk level used for planning and UX.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRiskLevel {
    /// Low-risk operation.
    Low,
    /// Medium-risk operation.
    Medium,
    /// High-risk operation.
    High,
    /// Critical-risk operation.
    Critical,
}

/// Safety tier used for normative enforcement behavior.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySafetyTier {
    /// Safe/read-mostly operation class.
    Safe,
    /// Risky/mutating operation class.
    Risky,
    /// Dangerous/destructive operation class.
    Dangerous,
    /// Critical system operation.
    Critical,
    /// Forbidden by default until explicitly reviewed.
    Forbidden,
}

/// Method-level policy rule.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleOperationPolicyRule {
    /// Discovery method key pattern.
    ///
    /// Supported forms:
    /// - exact: `users.messages.send`
    /// - prefix wildcard: `users.messages.*`
    /// - catch-all: `*`
    pub operation_pattern: String,
    /// Capability identifier assigned to matching methods.
    pub capability: String,
    /// Risk level for matching methods.
    pub risk_level: PolicyRiskLevel,
    /// Safety tier for matching methods.
    pub safety_tier: PolicySafetyTier,
    /// Approval mode for matching methods.
    pub approval_mode: PolicyApprovalMode,
    /// Required OAuth scopes (empty when API key auth is expected).
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// Additional rule notes.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Service-level policy profile.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleServicePolicy {
    /// Discovery API service name (for example `gmail`).
    pub service: String,
    /// Discovery API versions covered by this profile.
    pub api_versions: Vec<String>,
    /// Recommended deployment zones for this service.
    pub recommended_zones: Vec<String>,
    /// Default host allowlist for methods in this service.
    pub host_allow: Vec<String>,
    /// Service carve-outs and exceptions.
    #[serde(default)]
    pub exceptions: Vec<String>,
    /// Method policy rules.
    pub rules: Vec<GoogleOperationPolicyRule>,
}

/// Policy contract for handwritten helper overlays above generated operations.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleHelperOverlayPolicy {
    /// Strict policy intent statement.
    pub intent: String,
    /// Criteria that must all be true before adding a handwritten helper.
    pub require_all: Vec<String>,
    /// Explicitly forbidden helper patterns.
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
    /// Review checklist that each helper overlay must satisfy.
    pub review_checklist: Vec<String>,
    /// Initial shortlisted workflows that justify helper overlays.
    pub initial_workflow_shortlist: Vec<GoogleHelperOverlayWorkflow>,
}

/// One high-value workflow entry where a helper overlay is justified.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleHelperOverlayWorkflow {
    /// Stable workflow identifier.
    pub workflow_id: String,
    /// Discovery service name for this workflow.
    pub service: String,
    /// Human-readable summary.
    pub summary: String,
    /// Discovery operation keys used by the workflow.
    pub operation_dependencies: Vec<String>,
    /// Capability IDs expected across the workflow.
    pub required_capabilities: Vec<String>,
    /// Additional workflow-level safety constraints.
    #[serde(default)]
    pub safety_constraints: Vec<String>,
    /// Rationale for why a handwritten overlay is warranted.
    pub rationale: Vec<String>,
}

/// Provisioning/setup policy contract for Google surfaces.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleProvisioningPolicy {
    /// Strict provisioning intent statement.
    pub intent: String,
    /// Narrow-by-default scope posture used for setup UX.
    pub default_scope_posture: String,
    /// Consent/verification rules that the setup UX must enforce.
    pub consent_restriction_rules: Vec<String>,
    /// Separation rules between provisioning-time auth sources and runtime auth.
    pub runtime_separation_rules: Vec<String>,
    /// `gcloud` automation boundary for project/bootstrap steps.
    pub gcloud_automation_boundary: GoogleGcloudAutomationBoundary,
    /// Per-surface provisioning profiles.
    pub surfaces: Vec<GoogleProvisioningSurfacePolicy>,
}

/// Project/bootstrap steps that `gcloud` may or may not automate.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleGcloudAutomationBoundary {
    /// Steps that may be automated through `gcloud`.
    pub automatable_steps: Vec<String>,
    /// Steps that must never be automated or bypassed.
    pub forbidden_steps: Vec<String>,
    /// Fallback policy when `gcloud` is unavailable or blocked.
    pub fallback_policy: Vec<String>,
}

/// Provisioning profile for one Google connector/setup surface.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleProvisioningSurfacePolicy {
    /// Stable provisioning surface identifier.
    pub surface_id: String,
    /// Human-readable surface name.
    pub display_name: String,
    /// Narrowest default scope set for this surface.
    pub default_scopes: Vec<String>,
    /// APIs that must be enabled before the connector is usable.
    pub required_api_enablement: Vec<String>,
    /// Additional project/bootstrap prerequisites.
    #[serde(default)]
    pub project_prerequisites: Vec<String>,
    /// Explicit scope-escalation paths above the default scope set.
    pub escalation_paths: Vec<GoogleProvisioningScopeEscalation>,
    /// Steps where `gcloud` materially reduces setup friction.
    pub gcloud_assisted_steps: Vec<String>,
    /// Deterministic fallback when `gcloud` cannot be used.
    pub fallback_steps: Vec<String>,
    /// How provisioning materializes runtime-safe auth/config state.
    pub runtime_materialization: Vec<String>,
    /// Additional implementation notes.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Triggered scope escalation for a provisioning surface.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoogleProvisioningScopeEscalation {
    /// Human-readable escalation trigger.
    pub trigger: String,
    /// Additional scopes granted when the trigger is accepted.
    pub add_scopes: Vec<String>,
    /// Extra notes about the escalation path.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Top-level policy catalog consumed by generation workflows.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GooglePolicyCatalog {
    /// Catalog version stamp.
    pub version: String,
    /// Bead that produced this catalog revision.
    pub generated_from_bead: String,
    /// Provisioning/setup baseline for Google surfaces.
    pub provisioning_policy: GoogleProvisioningPolicy,
    /// Strict policy + shortlist for handwritten helper overlays.
    pub helper_overlay_policy: GoogleHelperOverlayPolicy,
    /// Service policy entries.
    pub services: Vec<GoogleServicePolicy>,
}

/// Service + rule pair selected for a method.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolvedGooglePolicyRule<'a> {
    /// Matched service profile.
    pub service: &'a GoogleServicePolicy,
    /// Matched method rule.
    pub rule: &'a GoogleOperationPolicyRule,
}

impl GooglePolicyCatalog {
    /// Parse and validate a policy catalog from JSON.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCatalogError`] if JSON decoding or validation fails.
    pub fn from_json_str(input: &str) -> Result<Self, PolicyCatalogError> {
        let catalog = serde_json::from_str::<Self>(input)
            .map_err(|source| PolicyCatalogError::JsonDecode { source })?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Load the embedded default catalog.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCatalogError`] if the embedded catalog is invalid.
    pub fn load_default() -> Result<Self, PolicyCatalogError> {
        Self::from_json_str(DEFAULT_POLICY_MATRIX_JSON)
    }

    /// Find service profile by canonical Discovery API name.
    #[must_use]
    pub fn service(&self, service_api_name: &str) -> Option<&GoogleServicePolicy> {
        self.services
            .iter()
            .find(|service| service.service == service_api_name)
    }

    /// Read-only helper-overlay policy contract.
    #[must_use]
    pub const fn helper_overlay_policy(&self) -> &GoogleHelperOverlayPolicy {
        &self.helper_overlay_policy
    }

    /// Read-only provisioning/setup policy contract.
    #[must_use]
    pub const fn provisioning_policy(&self) -> &GoogleProvisioningPolicy {
        &self.provisioning_policy
    }

    /// Return provisioning surface policy by stable id.
    #[must_use]
    pub fn provisioning_surface(
        &self,
        surface_id: &str,
    ) -> Option<&GoogleProvisioningSurfacePolicy> {
        self.provisioning_policy
            .surfaces
            .iter()
            .find(|surface| surface.surface_id == surface_id)
    }

    /// Return helper-workflow shortlist entries for a given service.
    #[must_use]
    pub fn helper_workflows_for_service(
        &self,
        service_api_name: &str,
    ) -> Vec<&GoogleHelperOverlayWorkflow> {
        self.helper_overlay_policy
            .initial_workflow_shortlist
            .iter()
            .filter(|workflow| workflow.service == service_api_name)
            .collect()
    }

    /// Classify a Discovery method key under a canonical service name.
    #[must_use]
    pub fn classify_operation(
        &self,
        service_api_name: &str,
        operation_key: &str,
    ) -> Option<ResolvedGooglePolicyRule<'_>> {
        let service = self.service(service_api_name)?;
        let rule = service
            .rules
            .iter()
            .filter(|rule| rule_matches(&rule.operation_pattern, operation_key))
            .max_by_key(|rule| pattern_specificity(&rule.operation_pattern))?;

        Some(ResolvedGooglePolicyRule { service, rule })
    }

    /// Resolve service selector (`alias` or `service:version`) then classify method.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] when service selector resolution fails.
    pub fn classify_selector_operation(
        &self,
        selector: &str,
        aliases: &ServiceAliasRegistry,
        operation_key: &str,
    ) -> Result<Option<ResolvedGooglePolicyRule<'_>>, DiscoveryError> {
        let service = aliases.resolve(selector)?;
        Ok(self.classify_operation(&service.api_name, operation_key))
    }

    fn validate(&self) -> Result<(), PolicyCatalogError> {
        if self.version.trim().is_empty() {
            return Err(PolicyCatalogError::Invalid {
                message: "catalog version must not be empty".to_string(),
            });
        }

        if self.generated_from_bead.trim().is_empty() {
            return Err(PolicyCatalogError::Invalid {
                message: "generated_from_bead must not be empty".to_string(),
            });
        }

        if self.services.is_empty() {
            return Err(PolicyCatalogError::Invalid {
                message: "services must not be empty".to_string(),
            });
        }

        let seen_service = self.validate_services()?;
        self.validate_provisioning_policy()?;
        self.validate_helper_overlay_policy(&seen_service)?;
        Ok(())
    }

    fn validate_services(&self) -> Result<BTreeSet<String>, PolicyCatalogError> {
        let mut seen_service = BTreeSet::new();
        for service in &self.services {
            if service.service.trim().is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: "service name must not be empty".to_string(),
                });
            }
            if !seen_service.insert(service.service.clone()) {
                return Err(PolicyCatalogError::Invalid {
                    message: format!("duplicate service entry `{}`", service.service),
                });
            }
            if service.api_versions.is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "service `{}` must declare at least one api_version",
                        service.service
                    ),
                });
            }
            if service.recommended_zones.is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "service `{}` must declare at least one recommended zone",
                        service.service
                    ),
                });
            }
            if service.host_allow.is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "service `{}` must declare at least one host_allow entry",
                        service.service
                    ),
                });
            }
            if service.rules.is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "service `{}` must declare at least one rule",
                        service.service
                    ),
                });
            }

            for rule in &service.rules {
                if rule.operation_pattern.trim().is_empty() {
                    return Err(PolicyCatalogError::Invalid {
                        message: format!(
                            "service `{}` contains rule with empty operation_pattern",
                            service.service
                        ),
                    });
                }
                if rule.capability.trim().is_empty() {
                    return Err(PolicyCatalogError::Invalid {
                        message: format!(
                            "service `{}` contains rule `{}` with empty capability",
                            service.service, rule.operation_pattern
                        ),
                    });
                }
            }
        }

        Ok(seen_service)
    }

    #[allow(clippy::too_many_lines)]
    fn validate_provisioning_policy(&self) -> Result<(), PolicyCatalogError> {
        let policy = &self.provisioning_policy;
        if policy.intent.trim().is_empty() {
            return Err(PolicyCatalogError::Invalid {
                message: "provisioning_policy.intent must not be empty".to_string(),
            });
        }

        if policy.default_scope_posture.trim().is_empty() {
            return Err(PolicyCatalogError::Invalid {
                message: "provisioning_policy.default_scope_posture must not be empty".to_string(),
            });
        }

        validate_non_empty_entries(
            "provisioning_policy.consent_restriction_rules",
            &policy.consent_restriction_rules,
        )?;
        validate_non_empty_entries(
            "provisioning_policy.runtime_separation_rules",
            &policy.runtime_separation_rules,
        )?;
        validate_non_empty_entries(
            "provisioning_policy.gcloud_automation_boundary.automatable_steps",
            &policy.gcloud_automation_boundary.automatable_steps,
        )?;
        validate_non_empty_entries(
            "provisioning_policy.gcloud_automation_boundary.forbidden_steps",
            &policy.gcloud_automation_boundary.forbidden_steps,
        )?;
        validate_non_empty_entries(
            "provisioning_policy.gcloud_automation_boundary.fallback_policy",
            &policy.gcloud_automation_boundary.fallback_policy,
        )?;

        if policy.surfaces.is_empty() {
            return Err(PolicyCatalogError::Invalid {
                message: "provisioning_policy.surfaces must not be empty".to_string(),
            });
        }

        let mut seen_surface_id = BTreeSet::new();
        for surface in &policy.surfaces {
            if surface.surface_id.trim().is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: "provisioning_policy contains surface with empty surface_id"
                        .to_string(),
                });
            }
            if !seen_surface_id.insert(surface.surface_id.clone()) {
                return Err(PolicyCatalogError::Invalid {
                    message: format!("duplicate provisioning surface `{}`", surface.surface_id),
                });
            }
            if surface.display_name.trim().is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "provisioning surface `{}` has empty display_name",
                        surface.surface_id
                    ),
                });
            }

            validate_non_empty_entries(
                &format!(
                    "provisioning surface `{}` default_scopes",
                    surface.surface_id
                ),
                &surface.default_scopes,
            )?;
            validate_non_empty_entries(
                &format!(
                    "provisioning surface `{}` required_api_enablement",
                    surface.surface_id
                ),
                &surface.required_api_enablement,
            )?;
            validate_non_empty_entries(
                &format!(
                    "provisioning surface `{}` gcloud_assisted_steps",
                    surface.surface_id
                ),
                &surface.gcloud_assisted_steps,
            )?;
            validate_non_empty_entries(
                &format!(
                    "provisioning surface `{}` fallback_steps",
                    surface.surface_id
                ),
                &surface.fallback_steps,
            )?;
            validate_non_empty_entries(
                &format!(
                    "provisioning surface `{}` runtime_materialization",
                    surface.surface_id
                ),
                &surface.runtime_materialization,
            )?;

            if surface.escalation_paths.is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "provisioning surface `{}` must declare escalation_paths",
                        surface.surface_id
                    ),
                });
            }

            let mut seen_default_scope = BTreeSet::new();
            for scope in &surface.default_scopes {
                let trimmed = scope.trim();
                if !seen_default_scope.insert(trimmed.to_string()) {
                    return Err(PolicyCatalogError::Invalid {
                        message: format!(
                            "provisioning surface `{}` repeats default scope `{trimmed}`",
                            surface.surface_id
                        ),
                    });
                }
            }

            let mut seen_trigger = BTreeSet::new();
            for escalation in &surface.escalation_paths {
                if escalation.trigger.trim().is_empty() {
                    return Err(PolicyCatalogError::Invalid {
                        message: format!(
                            "provisioning surface `{}` has escalation with empty trigger",
                            surface.surface_id
                        ),
                    });
                }
                if !seen_trigger.insert(escalation.trigger.clone()) {
                    return Err(PolicyCatalogError::Invalid {
                        message: format!(
                            "provisioning surface `{}` repeats escalation trigger `{}`",
                            surface.surface_id, escalation.trigger
                        ),
                    });
                }
                validate_non_empty_entries(
                    &format!(
                        "provisioning surface `{}` escalation `{}` add_scopes",
                        surface.surface_id, escalation.trigger
                    ),
                    &escalation.add_scopes,
                )?;

                let mut seen_add_scope = BTreeSet::new();
                for scope in &escalation.add_scopes {
                    let trimmed = scope.trim();
                    if !seen_add_scope.insert(trimmed.to_string()) {
                        return Err(PolicyCatalogError::Invalid {
                            message: format!(
                                "provisioning surface `{}` escalation `{}` repeats scope `{trimmed}`",
                                surface.surface_id, escalation.trigger
                            ),
                        });
                    }
                    if seen_default_scope.contains(trimmed) {
                        return Err(PolicyCatalogError::Invalid {
                            message: format!(
                                "provisioning surface `{}` escalation `{}` repeats default scope `{trimmed}`",
                                surface.surface_id, escalation.trigger
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_helper_overlay_policy(
        &self,
        seen_service: &BTreeSet<String>,
    ) -> Result<(), PolicyCatalogError> {
        if self.helper_overlay_policy.intent.trim().is_empty() {
            return Err(PolicyCatalogError::Invalid {
                message: "helper_overlay_policy.intent must not be empty".to_string(),
            });
        }

        if self.helper_overlay_policy.require_all.is_empty() {
            return Err(PolicyCatalogError::Invalid {
                message: "helper_overlay_policy.require_all must not be empty".to_string(),
            });
        }

        if self.helper_overlay_policy.review_checklist.is_empty() {
            return Err(PolicyCatalogError::Invalid {
                message: "helper_overlay_policy.review_checklist must not be empty".to_string(),
            });
        }

        if self
            .helper_overlay_policy
            .initial_workflow_shortlist
            .is_empty()
        {
            return Err(PolicyCatalogError::Invalid {
                message: "helper_overlay_policy.initial_workflow_shortlist must not be empty"
                    .to_string(),
            });
        }

        let mut seen_workflow_id = BTreeSet::new();
        for workflow in &self.helper_overlay_policy.initial_workflow_shortlist {
            if workflow.workflow_id.trim().is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: "helper shortlist contains workflow with empty workflow_id"
                        .to_string(),
                });
            }
            if !seen_workflow_id.insert(workflow.workflow_id.clone()) {
                return Err(PolicyCatalogError::Invalid {
                    message: format!("duplicate helper workflow `{}`", workflow.workflow_id),
                });
            }
            if workflow.service.trim().is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "helper workflow `{}` has empty service",
                        workflow.workflow_id
                    ),
                });
            }
            if !seen_service.contains(&workflow.service) {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "helper workflow `{}` references unknown service `{}`",
                        workflow.workflow_id, workflow.service
                    ),
                });
            }
            if workflow.summary.trim().is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "helper workflow `{}` has empty summary",
                        workflow.workflow_id
                    ),
                });
            }
            if workflow.operation_dependencies.is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "helper workflow `{}` must declare operation_dependencies",
                        workflow.workflow_id
                    ),
                });
            }
            if workflow.required_capabilities.is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "helper workflow `{}` must declare required_capabilities",
                        workflow.workflow_id
                    ),
                });
            }
            if workflow.rationale.is_empty() {
                return Err(PolicyCatalogError::Invalid {
                    message: format!(
                        "helper workflow `{}` must declare rationale",
                        workflow.workflow_id
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Load and validate the embedded default catalog.
///
/// # Panics
///
/// Panics if the embedded JSON policy catalog is invalid.
#[must_use]
pub fn default_google_policy_catalog() -> GooglePolicyCatalog {
    GooglePolicyCatalog::load_default().expect("embedded google policy catalog must be valid")
}

fn validate_non_empty_entries(
    field_name: &str,
    values: &[String],
) -> Result<(), PolicyCatalogError> {
    if values.is_empty() {
        return Err(PolicyCatalogError::Invalid {
            message: format!("{field_name} must not be empty"),
        });
    }

    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(PolicyCatalogError::Invalid {
            message: format!("{field_name} must not contain empty entries"),
        });
    }

    Ok(())
}

fn rule_matches(pattern: &str, operation_key: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return operation_key.starts_with(prefix);
    }

    operation_key == pattern
}

fn pattern_specificity(pattern: &str) -> (u8, usize) {
    if pattern == "*" {
        return (0, 0);
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return (1, prefix.len());
    }

    (2, pattern.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_loads_and_contains_expected_services() {
        let catalog = default_google_policy_catalog();
        assert_eq!(
            catalog.generated_from_bead,
            "flywheel_connectors-lszk.45.1.8.1"
        );
        assert!(catalog.service("gmail").is_some());
        assert!(catalog.service("calendar").is_some());
        assert!(catalog.service("youtube").is_some());
        assert!(catalog.service("bigquery").is_some());
        assert!(catalog.service("generativelanguage").is_some());
        assert!(!catalog.provisioning_policy.default_scope_posture.is_empty());
        assert!(catalog.provisioning_surface("gmail").is_some());
        assert!(catalog.provisioning_surface("calendar").is_some());
        assert!(catalog.provisioning_surface("workspace_events").is_some());
        assert!(!catalog.helper_overlay_policy.require_all.is_empty());
        assert!(
            !catalog
                .helper_overlay_policy
                .initial_workflow_shortlist
                .is_empty()
        );
    }

    #[test]
    fn helper_shortlist_references_known_services_and_supports_lookup() {
        let catalog = default_google_policy_catalog();
        for workflow in &catalog.helper_overlay_policy.initial_workflow_shortlist {
            assert!(
                catalog.service(&workflow.service).is_some(),
                "unknown service {} in workflow {}",
                workflow.service,
                workflow.workflow_id
            );
            assert!(!workflow.operation_dependencies.is_empty());
            assert!(!workflow.required_capabilities.is_empty());
            assert!(!workflow.rationale.is_empty());
        }

        let gmail_workflows = catalog.helper_workflows_for_service("gmail");
        assert!(!gmail_workflows.is_empty());
        assert!(
            gmail_workflows
                .iter()
                .any(|workflow| workflow.workflow_id == "gmail.sync_history_checkpointed")
        );
    }

    #[test]
    fn provisioning_surfaces_support_lookup_and_escalation_policy() {
        let catalog = default_google_policy_catalog();
        let gmail = catalog
            .provisioning_surface("gmail")
            .expect("gmail provisioning surface should exist");
        assert_eq!(gmail.display_name, "Gmail connector provisioning");
        assert!(!gmail.default_scopes.is_empty());
        assert!(
            gmail
                .escalation_paths
                .iter()
                .any(|path| path.trigger.contains("outbound send"))
        );
    }

    #[test]
    fn classify_operation_prefers_exact_rule_over_wildcards() {
        let catalog = default_google_policy_catalog();
        let matched = catalog
            .classify_operation("gmail", "users.messages.send")
            .expect("gmail send must map");

        assert_eq!(matched.rule.operation_pattern, "users.messages.send");
        assert_eq!(matched.rule.capability, "gmail.send");
        assert_eq!(matched.rule.safety_tier, PolicySafetyTier::Dangerous);
        assert_eq!(matched.rule.approval_mode, PolicyApprovalMode::Interactive);
    }

    #[test]
    fn classify_operation_uses_prefix_wildcard() {
        let catalog = default_google_policy_catalog();
        let matched = catalog
            .classify_operation("calendar", "events.instances")
            .expect("calendar events instances should match wildcard");

        assert_eq!(matched.rule.operation_pattern, "events.*");
        assert_eq!(matched.rule.capability, "gcal.read");
        assert_eq!(matched.rule.safety_tier, PolicySafetyTier::Safe);
    }

    #[test]
    fn classify_operation_falls_back_to_catch_all() {
        let catalog = default_google_policy_catalog();
        let matched = catalog
            .classify_operation("youtube", "mystery.unmappedMethod")
            .expect("youtube catch-all rule should apply");

        assert_eq!(matched.rule.operation_pattern, "*");
        assert_eq!(matched.rule.capability, "google.review_required");
        assert_eq!(matched.rule.safety_tier, PolicySafetyTier::Forbidden);
    }

    #[test]
    fn classify_selector_supports_alias_resolution() {
        let catalog = default_google_policy_catalog();
        let aliases = ServiceAliasRegistry::default();
        let matched = catalog
            .classify_selector_operation("gcal", &aliases, "events.insert")
            .expect("alias resolution should succeed")
            .expect("rule should exist");

        assert_eq!(matched.service.service, "calendar");
        assert_eq!(matched.rule.capability, "gcal.write");
    }

    #[test]
    fn catalog_serialization_is_deterministic() {
        let first = default_google_policy_catalog();
        let second = default_google_policy_catalog();

        let first_json = serde_json::to_string(&first).expect("serialize first");
        let second_json = serde_json::to_string(&second).expect("serialize second");

        assert_eq!(first_json, second_json);
    }

    // ---------------------------------------------------------------
    // Helper: build a minimal valid GooglePolicyCatalog for mutations
    // ---------------------------------------------------------------

    fn build_minimal_valid_catalog() -> GooglePolicyCatalog {
        GooglePolicyCatalog {
            version: "1.0.0".to_string(),
            generated_from_bead: "test-bead-0001".to_string(),
            provisioning_policy: GoogleProvisioningPolicy {
                intent: "test provisioning intent".to_string(),
                default_scope_posture: "start narrow".to_string(),
                consent_restriction_rules: vec!["rule-a".to_string()],
                runtime_separation_rules: vec!["runtime-a".to_string()],
                gcloud_automation_boundary: GoogleGcloudAutomationBoundary {
                    automatable_steps: vec!["enable apis".to_string()],
                    forbidden_steps: vec!["skip consent".to_string()],
                    fallback_policy: vec!["emit manual steps".to_string()],
                },
                surfaces: vec![GoogleProvisioningSurfacePolicy {
                    surface_id: "gmail".to_string(),
                    display_name: "Gmail test setup".to_string(),
                    default_scopes: vec!["scope.read".to_string()],
                    required_api_enablement: vec!["Gmail API".to_string()],
                    project_prerequisites: vec!["oauth client exists".to_string()],
                    escalation_paths: vec![GoogleProvisioningScopeEscalation {
                        trigger: "enable send".to_string(),
                        add_scopes: vec!["scope.send".to_string()],
                        notes: vec!["send is opt-in".to_string()],
                    }],
                    gcloud_assisted_steps: vec!["check project".to_string()],
                    fallback_steps: vec!["show console steps".to_string()],
                    runtime_materialization: vec!["emit credential_id".to_string()],
                    notes: vec!["test note".to_string()],
                }],
            },
            helper_overlay_policy: GoogleHelperOverlayPolicy {
                intent: "test intent".to_string(),
                require_all: vec!["req-a".to_string()],
                forbidden_patterns: vec![],
                review_checklist: vec!["check-a".to_string()],
                initial_workflow_shortlist: vec![GoogleHelperOverlayWorkflow {
                    workflow_id: "wf.test".to_string(),
                    service: "testsvc".to_string(),
                    summary: "A test workflow".to_string(),
                    operation_dependencies: vec!["items.list".to_string()],
                    required_capabilities: vec!["testsvc.read".to_string()],
                    safety_constraints: vec![],
                    rationale: vec!["needed for testing".to_string()],
                }],
            },
            services: vec![GoogleServicePolicy {
                service: "testsvc".to_string(),
                api_versions: vec!["v1".to_string()],
                recommended_zones: vec!["us-central1".to_string()],
                host_allow: vec!["testsvc.googleapis.com".to_string()],
                exceptions: vec![],
                rules: vec![
                    GoogleOperationPolicyRule {
                        operation_pattern: "items.list".to_string(),
                        capability: "testsvc.read".to_string(),
                        risk_level: PolicyRiskLevel::Low,
                        safety_tier: PolicySafetyTier::Safe,
                        approval_mode: PolicyApprovalMode::None,
                        required_scopes: vec![],
                        notes: vec![],
                    },
                    GoogleOperationPolicyRule {
                        operation_pattern: "items.*".to_string(),
                        capability: "testsvc.items".to_string(),
                        risk_level: PolicyRiskLevel::Medium,
                        safety_tier: PolicySafetyTier::Risky,
                        approval_mode: PolicyApprovalMode::Policy,
                        required_scopes: vec![],
                        notes: vec![],
                    },
                    GoogleOperationPolicyRule {
                        operation_pattern: "*".to_string(),
                        capability: "testsvc.catch_all".to_string(),
                        risk_level: PolicyRiskLevel::High,
                        safety_tier: PolicySafetyTier::Forbidden,
                        approval_mode: PolicyApprovalMode::Interactive,
                        required_scopes: vec![],
                        notes: vec![],
                    },
                ],
            }],
        }
    }

    // ---------------------------------------------------------------
    // PolicyCatalogError Display
    // ---------------------------------------------------------------

    #[test]
    fn policy_catalog_error_display_json_decode() {
        let bad_json = "not json at all {{{";
        let err = serde_json::from_str::<GooglePolicyCatalog>(bad_json).unwrap_err();
        let catalog_err = PolicyCatalogError::JsonDecode { source: err };
        let msg = format!("{catalog_err}");
        assert!(
            msg.contains("failed to parse policy catalog JSON"),
            "unexpected Display: {msg}"
        );
    }

    #[test]
    fn policy_catalog_error_display_invalid() {
        let err = PolicyCatalogError::Invalid {
            message: "something went wrong".to_string(),
        };
        let msg = format!("{err}");
        assert_eq!(msg, "invalid policy catalog: something went wrong");
    }

    // ---------------------------------------------------------------
    // PolicyApprovalMode
    // ---------------------------------------------------------------

    #[test]
    fn approval_mode_serde_roundtrip_all_variants() {
        let variants = [
            PolicyApprovalMode::None,
            PolicyApprovalMode::Policy,
            PolicyApprovalMode::Interactive,
            PolicyApprovalMode::ElevationToken,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).expect("serialize");
            let back: PolicyApprovalMode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*variant, back, "roundtrip failed for {json}");
        }
    }

    #[test]
    fn approval_mode_ord_ordering() {
        assert!(PolicyApprovalMode::None < PolicyApprovalMode::Policy);
        assert!(PolicyApprovalMode::Policy < PolicyApprovalMode::Interactive);
        assert!(PolicyApprovalMode::Interactive < PolicyApprovalMode::ElevationToken);
    }

    // ---------------------------------------------------------------
    // PolicyRiskLevel
    // ---------------------------------------------------------------

    #[test]
    fn risk_level_serde_roundtrip_all_variants() {
        let variants = [
            PolicyRiskLevel::Low,
            PolicyRiskLevel::Medium,
            PolicyRiskLevel::High,
            PolicyRiskLevel::Critical,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).expect("serialize");
            let back: PolicyRiskLevel = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*variant, back, "roundtrip failed for {json}");
        }
    }

    #[test]
    fn risk_level_ord_ordering() {
        assert!(PolicyRiskLevel::Low < PolicyRiskLevel::Medium);
        assert!(PolicyRiskLevel::Medium < PolicyRiskLevel::High);
        assert!(PolicyRiskLevel::High < PolicyRiskLevel::Critical);
    }

    // ---------------------------------------------------------------
    // PolicySafetyTier
    // ---------------------------------------------------------------

    #[test]
    fn safety_tier_serde_roundtrip_all_variants() {
        let variants = [
            PolicySafetyTier::Safe,
            PolicySafetyTier::Risky,
            PolicySafetyTier::Dangerous,
            PolicySafetyTier::Critical,
            PolicySafetyTier::Forbidden,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).expect("serialize");
            let back: PolicySafetyTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*variant, back, "roundtrip failed for {json}");
        }
    }

    #[test]
    fn safety_tier_ord_ordering() {
        assert!(PolicySafetyTier::Safe < PolicySafetyTier::Risky);
        assert!(PolicySafetyTier::Risky < PolicySafetyTier::Dangerous);
        assert!(PolicySafetyTier::Dangerous < PolicySafetyTier::Critical);
        assert!(PolicySafetyTier::Critical < PolicySafetyTier::Forbidden);
    }

    // ---------------------------------------------------------------
    // GooglePolicyCatalog validation
    // ---------------------------------------------------------------

    #[test]
    fn validate_rejects_empty_version() {
        let mut cat = build_minimal_valid_catalog();
        cat.version = "  ".to_string();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("version must not be empty"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_empty_generated_from_bead() {
        let mut cat = build_minimal_valid_catalog();
        cat.generated_from_bead = String::new();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("generated_from_bead must not be empty"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_empty_services() {
        let mut cat = build_minimal_valid_catalog();
        cat.services.clear();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("services must not be empty"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_duplicate_service() {
        let mut cat = build_minimal_valid_catalog();
        let dup = cat.services[0].clone();
        cat.services.push(dup);
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate service entry"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_empty_service_name() {
        let mut cat = build_minimal_valid_catalog();
        cat.services[0].service = "  ".to_string();
        // Also update the workflow service reference so we test service-name validation first
        cat.helper_overlay_policy.initial_workflow_shortlist[0].service = "  ".to_string();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("service name must not be empty"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_service_without_api_versions() {
        let mut cat = build_minimal_valid_catalog();
        cat.services[0].api_versions.clear();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("at least one api_version"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_service_without_zones() {
        let mut cat = build_minimal_valid_catalog();
        cat.services[0].recommended_zones.clear();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("at least one recommended zone"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_service_without_host_allow() {
        let mut cat = build_minimal_valid_catalog();
        cat.services[0].host_allow.clear();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("at least one host_allow entry"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_service_without_rules() {
        let mut cat = build_minimal_valid_catalog();
        cat.services[0].rules.clear();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("at least one rule"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_rule_with_empty_pattern() {
        let mut cat = build_minimal_valid_catalog();
        cat.services[0].rules[0].operation_pattern = "  ".to_string();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty operation_pattern"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_rule_with_empty_capability() {
        let mut cat = build_minimal_valid_catalog();
        cat.services[0].rules[0].capability = String::new();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty capability"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_empty_overlay_intent() {
        let mut cat = build_minimal_valid_catalog();
        cat.helper_overlay_policy.intent = "  ".to_string();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("helper_overlay_policy.intent must not be empty"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_empty_require_all() {
        let mut cat = build_minimal_valid_catalog();
        cat.helper_overlay_policy.require_all.clear();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("require_all must not be empty"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_empty_review_checklist() {
        let mut cat = build_minimal_valid_catalog();
        cat.helper_overlay_policy.review_checklist.clear();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("review_checklist must not be empty"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_empty_workflow_shortlist() {
        let mut cat = build_minimal_valid_catalog();
        cat.helper_overlay_policy.initial_workflow_shortlist.clear();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("initial_workflow_shortlist must not be empty"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_duplicate_workflow_id() {
        let mut cat = build_minimal_valid_catalog();
        let dup = cat.helper_overlay_policy.initial_workflow_shortlist[0].clone();
        cat.helper_overlay_policy
            .initial_workflow_shortlist
            .push(dup);
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate helper workflow"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_workflow_unknown_service() {
        let mut cat = build_minimal_valid_catalog();
        cat.helper_overlay_policy.initial_workflow_shortlist[0].service = "nonexistent".to_string();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown service"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_empty_provisioning_intent() {
        let mut cat = build_minimal_valid_catalog();
        cat.provisioning_policy.intent = "  ".to_string();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("provisioning_policy.intent must not be empty"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_duplicate_provisioning_surface() {
        let mut cat = build_minimal_valid_catalog();
        let dup = cat.provisioning_policy.surfaces[0].clone();
        cat.provisioning_policy.surfaces.push(dup);
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate provisioning surface"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_empty_default_scope_posture() {
        let mut cat = build_minimal_valid_catalog();
        cat.provisioning_policy.default_scope_posture = String::new();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("provisioning_policy.default_scope_posture must not be empty"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_empty_provisioning_surface_default_scopes() {
        let mut cat = build_minimal_valid_catalog();
        cat.provisioning_policy.surfaces[0].default_scopes.clear();
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("default_scopes must not be empty"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_provisioning_escalation_that_repeats_default_scope() {
        let mut cat = build_minimal_valid_catalog();
        cat.provisioning_policy.surfaces[0].escalation_paths[0].add_scopes =
            vec!["scope.read".to_string()];
        let err = cat.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("repeats default scope `scope.read`"),
            "got: {msg}"
        );
    }

    // ---------------------------------------------------------------
    // rule_matches and pattern_specificity
    // ---------------------------------------------------------------

    #[test]
    fn rule_matches_exact() {
        assert!(rule_matches("users.messages.send", "users.messages.send"));
    }

    #[test]
    fn rule_matches_prefix_wildcard() {
        assert!(rule_matches("items.*", "items.list"));
        assert!(rule_matches("items.*", "items.get"));
        assert!(!rule_matches("items.*", "other.list"));
    }

    #[test]
    fn rule_matches_catch_all() {
        assert!(rule_matches("*", "anything.at.all"));
        assert!(rule_matches("*", ""));
    }

    #[test]
    fn rule_matches_no_match() {
        assert!(!rule_matches("users.messages.send", "users.messages.list"));
        assert!(!rule_matches("items.*", "other.thing"));
    }

    #[test]
    fn pattern_specificity_exact_highest() {
        let exact = pattern_specificity("users.messages.send");
        let prefix = pattern_specificity("users.messages.*");
        let catch_all = pattern_specificity("*");
        assert!(exact > prefix, "exact should beat prefix");
        assert!(prefix > catch_all, "prefix should beat catch-all");
    }

    #[test]
    fn pattern_specificity_longer_prefix_wins() {
        let short = pattern_specificity("a.*");
        let long = pattern_specificity("a.b.c.*");
        assert!(long > short, "longer prefix should be more specific");
    }

    // ---------------------------------------------------------------
    // classify / helper_workflows lookups
    // ---------------------------------------------------------------

    #[test]
    fn classify_operation_unknown_service_returns_none() {
        let cat = build_minimal_valid_catalog();
        assert!(cat.classify_operation("nonexistent", "anything").is_none());
    }

    #[test]
    fn classify_operation_unknown_method_uses_catch_all() {
        let cat = build_minimal_valid_catalog();
        let resolved = cat
            .classify_operation("testsvc", "totally.unknown.method")
            .expect("catch-all should match");
        assert_eq!(resolved.rule.operation_pattern, "*");
        assert_eq!(resolved.rule.capability, "testsvc.catch_all");
    }

    #[test]
    fn classify_selector_unknown_alias_returns_error() {
        let cat = build_minimal_valid_catalog();
        let aliases = ServiceAliasRegistry::default();
        let result = cat.classify_selector_operation("zzz_not_real", &aliases, "op");
        assert!(result.is_err(), "expected error for unknown alias");
    }

    #[test]
    fn helper_workflows_for_unknown_service_returns_empty() {
        let cat = build_minimal_valid_catalog();
        let wfs = cat.helper_workflows_for_service("no_such_service");
        assert!(wfs.is_empty());
    }
}
