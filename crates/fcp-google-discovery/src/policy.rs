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

/// Top-level policy catalog consumed by generation workflows.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GooglePolicyCatalog {
    /// Catalog version stamp.
    pub version: String,
    /// Bead that produced this catalog revision.
    pub generated_from_bead: String,
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
            "flywheel_connectors-lszk.45.1.6"
        );
        assert!(catalog.service("gmail").is_some());
        assert!(catalog.service("calendar").is_some());
        assert!(catalog.service("youtube").is_some());
        assert!(catalog.service("bigquery").is_some());
        assert!(catalog.service("generativelanguage").is_some());
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
}
