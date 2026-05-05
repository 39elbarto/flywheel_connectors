//! Shared provider connector contract assertions.
//!
//! Provider-style connectors keep their connector-specific behavior in their
//! own crates, but many proof obligations are shared: stable auth/setup
//! metadata, unique env/config keys, explicit model catalogs/defaults, safe
//! base URLs, redaction-safe diagnostics, and no import-time registration side
//! effects. This module gives connector tests one typed place to express those
//! expectations without adding a generic provider runtime wrapper.

use std::collections::HashSet;
use std::fmt;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Exact OpenClaw/Hermes provider overlap targeted by the first migration pass.
pub const EXACT_OVERLAP_PROVIDER_IDS: &[&str] = &[
    "openai",
    "anthropic",
    "mistral",
    "openrouter",
    "huggingface",
    "deepgram",
    "elevenlabs",
    "exa",
    "firecrawl",
    "tavily",
];

/// One actionable provider-contract failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderContractViolation {
    /// Dot-path or JSON-pointer-like location of the failure.
    pub path: String,
    /// Human-readable failure details.
    pub message: String,
}

impl ProviderContractViolation {
    #[must_use]
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ProviderContractViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Aggregate provider-contract validation report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderContractReport {
    violations: Vec<ProviderContractViolation>,
}

impl ProviderContractReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether no violations were recorded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.violations.is_empty()
    }

    /// Recorded violations.
    #[must_use]
    pub fn violations(&self) -> &[ProviderContractViolation] {
        &self.violations
    }

    /// Consume the report and return all violations.
    #[must_use]
    pub fn into_violations(self) -> Vec<ProviderContractViolation> {
        self.violations
    }

    fn push(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.violations
            .push(ProviderContractViolation::new(path, message));
    }
}

impl fmt::Display for ProviderContractReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.violations.is_empty() {
            return write!(f, "provider contract passed");
        }

        writeln!(
            f,
            "provider contract failed with {} violation(s):",
            self.violations.len()
        )?;
        for violation in &self.violations {
            writeln!(f, "- {violation}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ProviderContractReport {}

/// Provider-contract validation result.
pub type ProviderContractResult = Result<(), ProviderContractReport>;

/// Auth metadata for a provider-style connector.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAuthMethodContract {
    /// Stable auth method id, for example `api_key` or `credential_id`.
    pub method_id: String,
    /// Operator-visible label.
    pub label: String,
    /// Optional operator hint. Empty hints are rejected when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Environment variable owned by this auth method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// Configure-payload key owned by this auth method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_key: Option<String>,
    /// Wizard choice id exposed by setup flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wizard_choice_id: Option<String>,
    /// Auth method id that the wizard choice resolves to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wizard_method_id: Option<String>,
    /// Model ids a setup/model-picker choice may expose.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_allowlist_allowed: Vec<String>,
    /// Initial model selections for the same allowlist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_allowlist_initial: Vec<String>,
    /// Provider-specific default model implied by this auth method, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
}

impl ProviderAuthMethodContract {
    /// Create a basic auth-method contract.
    #[must_use]
    pub fn new(method_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            method_id: method_id.into(),
            label: label.into(),
            ..Self::default()
        }
    }

    /// Attach an environment variable to this auth method.
    #[must_use]
    pub fn with_env_var(mut self, env_var: impl Into<String>) -> Self {
        self.env_var = Some(env_var.into());
        self
    }

    /// Attach a configure-payload key to this auth method.
    #[must_use]
    pub fn with_config_key(mut self, config_key: impl Into<String>) -> Self {
        self.config_key = Some(config_key.into());
        self
    }

    /// Attach wizard metadata to this auth method.
    #[must_use]
    pub fn with_wizard_choice(
        mut self,
        choice_id: impl Into<String>,
        method_id: impl Into<String>,
    ) -> Self {
        self.wizard_choice_id = Some(choice_id.into());
        self.wizard_method_id = Some(method_id.into());
        self
    }

    /// Attach an auth-method-level default model.
    #[must_use]
    pub fn with_default_model(mut self, model_id: impl Into<String>) -> Self {
        self.default_model = Some(model_id.into());
        self
    }
}

/// Provider-level setup or wizard choice.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSetupChoiceContract {
    /// Stable setup choice id.
    pub choice_id: String,
    /// Operator-visible setup label.
    pub label: String,
    /// Auth method id this choice resolves to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_id: Option<String>,
    /// Model ids this setup choice may expose.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_allowlist_allowed: Vec<String>,
    /// Initial model selections for the same allowlist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_allowlist_initial: Vec<String>,
}

impl ProviderSetupChoiceContract {
    /// Create a setup-choice contract.
    #[must_use]
    pub fn new(choice_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            choice_id: choice_id.into(),
            label: label.into(),
            ..Self::default()
        }
    }

    /// Declare which auth method this setup choice resolves to.
    #[must_use]
    pub fn with_method_id(mut self, method_id: impl Into<String>) -> Self {
        self.method_id = Some(method_id.into());
        self
    }
}

/// One model entry in a provider catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderModelContract {
    /// Provider-facing model id.
    pub model_id: String,
    /// Optional operator-visible model label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl ProviderModelContract {
    /// Create a model contract.
    #[must_use]
    pub fn new(model_id: impl Into<String>) -> Self {
        Self {
            model_id: model_id.into(),
            label: None,
        }
    }

    /// Attach an operator-visible label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// Provider model catalog metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderModelCatalogContract {
    /// Stable catalog id, for example `chat` or `voices`.
    pub catalog_id: String,
    /// Models known to the connector/test fixture.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<ProviderModelContract>,
    /// Whether an empty catalog is intentional because discovery is provider-owned.
    pub allow_dynamic_empty_catalog: bool,
}

impl ProviderModelCatalogContract {
    /// Create a model-catalog contract.
    #[must_use]
    pub fn new(catalog_id: impl Into<String>) -> Self {
        Self {
            catalog_id: catalog_id.into(),
            models: Vec::new(),
            allow_dynamic_empty_catalog: false,
        }
    }

    /// Add a model entry.
    #[must_use]
    pub fn with_model(mut self, model: ProviderModelContract) -> Self {
        self.models.push(model);
        self
    }

    /// Mark an empty catalog as intentional provider-owned discovery.
    #[must_use]
    pub const fn allow_dynamic_empty_catalog(mut self) -> Self {
        self.allow_dynamic_empty_catalog = true;
        self
    }
}

/// Per-operation model metadata, including schema defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderOperationContract {
    /// Stable FCP operation id.
    pub operation_id: String,
    /// Model catalog this operation draws from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_id: Option<String>,
    /// Input schema field used for model selection.
    pub model_field: String,
    /// Default model from operation schema or connector-level metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    /// Explicit reason when a default model is intentionally absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model_deferral: Option<String>,
    /// Whether either `default_model` or `default_model_deferral` is mandatory.
    pub requires_default_model: bool,
}

impl ProviderOperationContract {
    /// Create an operation contract.
    #[must_use]
    pub fn new(operation_id: impl Into<String>) -> Self {
        Self {
            operation_id: operation_id.into(),
            catalog_id: None,
            model_field: "model".to_owned(),
            default_model: None,
            default_model_deferral: None,
            requires_default_model: false,
        }
    }

    /// Create an operation contract by extracting `properties.model.default`
    /// from an FCP operation input schema.
    #[must_use]
    pub fn from_input_schema(
        operation_id: impl Into<String>,
        catalog_id: impl Into<String>,
        input_schema: &Value,
    ) -> Self {
        Self::new(operation_id)
            .with_catalog_id(catalog_id)
            .with_default_model_option(default_model_from_input_schema(input_schema))
    }

    /// Attach the model catalog used by this operation.
    #[must_use]
    pub fn with_catalog_id(mut self, catalog_id: impl Into<String>) -> Self {
        self.catalog_id = Some(catalog_id.into());
        self
    }

    /// Attach a default model.
    #[must_use]
    pub fn with_default_model(mut self, model_id: impl Into<String>) -> Self {
        self.default_model = Some(model_id.into());
        self
    }

    /// Attach an optional default model.
    #[must_use]
    pub fn with_default_model_option(mut self, model_id: Option<String>) -> Self {
        self.default_model = model_id;
        self
    }

    /// Record an intentional default-model deferral.
    #[must_use]
    pub fn with_default_model_deferral(mut self, reason: impl Into<String>) -> Self {
        self.default_model_deferral = Some(reason.into());
        self
    }

    /// Require this operation to publish a default or explicit deferral.
    #[must_use]
    pub const fn require_default_model(mut self) -> Self {
        self.requires_default_model = true;
        self
    }
}

/// Base URL metadata for provider request paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderBaseUrlContract {
    /// Stable name, for example `api` or `catalog`.
    pub name: String,
    /// URL value being validated.
    pub url: String,
    /// Whether plain HTTP loopback is allowed for local no-mock fixtures.
    pub allow_loopback_http: bool,
}

impl ProviderBaseUrlContract {
    /// Create a base-URL contract.
    #[must_use]
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            allow_loopback_http: false,
        }
    }

    /// Permit `http://localhost`, `http://127.0.0.1`, or `http://[::1]`.
    #[must_use]
    pub const fn allow_loopback_http(mut self) -> Self {
        self.allow_loopback_http = true;
        self
    }
}

/// Redaction payload that must not contain known secret markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRedactionPayload {
    /// Stable payload label.
    pub label: String,
    /// Structured payload to scan.
    pub payload: Value,
}

impl ProviderRedactionPayload {
    /// Create a redaction payload contract.
    #[must_use]
    pub fn new(label: impl Into<String>, payload: Value) -> Self {
        Self {
            label: label.into(),
            payload,
        }
    }
}

/// Import-time side-effect observation from connector/module tests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderImportSideEffectContract {
    /// Module or connector surface under test.
    pub module_id: String,
    /// Forbidden surface touched during import, for example `registry`.
    pub forbidden_surface: String,
    /// Observed calls. An empty list means no violation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_calls: Vec<String>,
    /// Why the side effect is banned.
    pub why: String,
    /// Actionable fix hint for connector authors.
    pub fix_hint: String,
}

impl ProviderImportSideEffectContract {
    /// Create an import side-effect contract.
    #[must_use]
    pub fn new(module_id: impl Into<String>, forbidden_surface: impl Into<String>) -> Self {
        Self {
            module_id: module_id.into(),
            forbidden_surface: forbidden_surface.into(),
            observed_calls: Vec::new(),
            why: "provider discovery/setup metadata must be descriptor-owned".to_owned(),
            fix_hint: "move registration into an explicit connector/testkit entry point".to_owned(),
        }
    }

    /// Record an observed import-time call.
    #[must_use]
    pub fn with_observed_call(mut self, call: impl Into<String>) -> Self {
        self.observed_calls.push(call.into());
        self
    }
}

/// Complete provider-contract fixture.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderContract {
    /// Stable provider id.
    pub provider_id: String,
    /// Operator-visible provider label.
    pub label: String,
    /// Optional docs path or docs URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_path: Option<String>,
    /// Provider aliases.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Provider-owned environment variables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_vars: Vec<String>,
    /// Provider-owned configure keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_keys: Vec<String>,
    /// Auth methods.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_methods: Vec<ProviderAuthMethodContract>,
    /// Provider-level setup choices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub setup_choices: Vec<ProviderSetupChoiceContract>,
    /// Auth method id used by the model picker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_picker_method_id: Option<String>,
    /// Provider-level default model for model pickers and diagnostics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    /// Model catalogs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_catalogs: Vec<ProviderModelCatalogContract>,
    /// Operation-level model defaults and deferrals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<ProviderOperationContract>,
    /// Provider API/catalog URLs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_urls: Vec<ProviderBaseUrlContract>,
    /// Secret markers that must not appear in redaction payloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_markers: Vec<String>,
    /// Redaction payloads to scan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redaction_payloads: Vec<ProviderRedactionPayload>,
    /// Import-time side-effect observations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub import_side_effects: Vec<ProviderImportSideEffectContract>,
}

impl ProviderContract {
    /// Create a provider contract.
    #[must_use]
    pub fn new(provider_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            label: label.into(),
            ..Self::default()
        }
    }

    /// Attach docs path or URL.
    #[must_use]
    pub fn with_docs_path(mut self, docs_path: impl Into<String>) -> Self {
        self.docs_path = Some(docs_path.into());
        self
    }

    /// Add an env var.
    #[must_use]
    pub fn with_env_var(mut self, env_var: impl Into<String>) -> Self {
        self.env_vars.push(env_var.into());
        self
    }

    /// Add a configure key.
    #[must_use]
    pub fn with_config_key(mut self, config_key: impl Into<String>) -> Self {
        self.config_keys.push(config_key.into());
        self
    }

    /// Add an auth method.
    #[must_use]
    pub fn with_auth_method(mut self, method: ProviderAuthMethodContract) -> Self {
        self.auth_methods.push(method);
        self
    }

    /// Add a setup choice.
    #[must_use]
    pub fn with_setup_choice(mut self, choice: ProviderSetupChoiceContract) -> Self {
        self.setup_choices.push(choice);
        self
    }

    /// Declare the model-picker auth method.
    #[must_use]
    pub fn with_model_picker_method(mut self, method_id: impl Into<String>) -> Self {
        self.model_picker_method_id = Some(method_id.into());
        self
    }

    /// Declare provider-level default model metadata.
    #[must_use]
    pub fn with_default_model(mut self, model_id: impl Into<String>) -> Self {
        self.default_model = Some(model_id.into());
        self
    }

    /// Add a model catalog.
    #[must_use]
    pub fn with_model_catalog(mut self, catalog: ProviderModelCatalogContract) -> Self {
        self.model_catalogs.push(catalog);
        self
    }

    /// Add an operation contract.
    #[must_use]
    pub fn with_operation(mut self, operation: ProviderOperationContract) -> Self {
        self.operations.push(operation);
        self
    }

    /// Add a base-URL contract.
    #[must_use]
    pub fn with_base_url(mut self, base_url: ProviderBaseUrlContract) -> Self {
        self.base_urls.push(base_url);
        self
    }

    /// Add a secret marker that must be redacted.
    #[must_use]
    pub fn with_secret_marker(mut self, marker: impl Into<String>) -> Self {
        self.secret_markers.push(marker.into());
        self
    }

    /// Add a redaction payload to scan.
    #[must_use]
    pub fn with_redaction_payload(mut self, payload: ProviderRedactionPayload) -> Self {
        self.redaction_payloads.push(payload);
        self
    }

    /// Add an import-time side-effect observation.
    #[must_use]
    pub fn with_import_side_effect(
        mut self,
        observation: ProviderImportSideEffectContract,
    ) -> Self {
        self.import_side_effects.push(observation);
        self
    }
}

/// Extract `properties.model.default` from an FCP operation input schema.
#[must_use]
pub fn default_model_from_input_schema(input_schema: &Value) -> Option<String> {
    input_schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("model"))
        .and_then(|model| model.get("default"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// Validate a provider contract and return every violation.
///
/// # Errors
///
/// Returns a [`ProviderContractReport`] when one or more contract violations are
/// found.
pub fn validate_provider_contract(contract: &ProviderContract) -> ProviderContractResult {
    let mut report = ProviderContractReport::new();

    validate_provider_identity(contract, &mut report);
    validate_unique_strings("aliases", &contract.aliases, &mut report);
    validate_unique_strings("env_vars", &contract.env_vars, &mut report);
    validate_unique_strings("config_keys", &contract.config_keys, &mut report);
    validate_auth_methods(contract, &mut report);
    validate_setup_choices(contract, &mut report);
    validate_catalogs(contract, &mut report);
    validate_default_model(
        "default_model",
        contract.default_model.as_deref(),
        None,
        contract,
        &mut report,
    );
    validate_operations(contract, &mut report);
    validate_base_urls(contract, &mut report);
    validate_redaction_payloads(contract, &mut report);
    validate_import_side_effects(contract, &mut report);

    if report.is_ok() { Ok(()) } else { Err(report) }
}

/// Assert that a provider contract is valid.
///
/// # Panics
///
/// Panics with a full violation report if the contract is invalid.
pub fn assert_provider_contract(contract: &ProviderContract) {
    if let Err(report) = validate_provider_contract(contract) {
        assert!(report.is_ok(), "{report}");
    }
}

fn validate_provider_identity(contract: &ProviderContract, report: &mut ProviderContractReport) {
    validate_non_empty("provider_id", &contract.provider_id, report);
    if !is_provider_id(&contract.provider_id) {
        report.push(
            "provider_id",
            "must start with a lowercase ASCII letter or digit and contain only lowercase ASCII letters, digits, '.', '_' or '-'",
        );
    }
    validate_non_empty("label", &contract.label, report);
    if let Some(docs_path) = &contract.docs_path {
        let trimmed = docs_path.trim();
        if trimmed.is_empty() {
            report.push("docs_path", "must not be empty when present");
        } else if !(trimmed.starts_with('/') || trimmed.starts_with("https://")) {
            report.push("docs_path", "must be an absolute docs path or HTTPS URL");
        }
    }
}

fn validate_auth_methods(contract: &ProviderContract, report: &mut ProviderContractReport) {
    let auth_ids: Vec<String> = contract
        .auth_methods
        .iter()
        .map(|method| method.method_id.clone())
        .collect();
    validate_unique_strings("auth_methods.method_id", &auth_ids, report);

    let mut wizard_choice_ids = Vec::new();
    for (index, method) in contract.auth_methods.iter().enumerate() {
        let path = format!("auth_methods[{index}]");
        validate_non_empty(format!("{path}.method_id"), &method.method_id, report);
        validate_non_empty(format!("{path}.label"), &method.label, report);
        validate_optional_non_empty(format!("{path}.hint"), method.hint.as_deref(), report);

        if let Some(env_var) = &method.env_var {
            validate_non_empty(format!("{path}.env_var"), env_var, report);
            if !contains_string(&contract.env_vars, env_var) {
                report.push(
                    format!("{path}.env_var"),
                    "auth env var must also appear in provider env_vars",
                );
            }
        }
        if let Some(config_key) = &method.config_key {
            validate_non_empty(format!("{path}.config_key"), config_key, report);
            if !contains_string(&contract.config_keys, config_key) {
                report.push(
                    format!("{path}.config_key"),
                    "auth config key must also appear in provider config_keys",
                );
            }
        }

        if let Some(choice_id) = &method.wizard_choice_id {
            wizard_choice_ids.push(choice_id.clone());
            validate_non_empty(format!("{path}.wizard_choice_id"), choice_id, report);
        }
        if let Some(method_id) = &method.wizard_method_id {
            validate_method_ref(
                format!("{path}.wizard_method_id"),
                method_id,
                contract,
                report,
            );
        }
        validate_model_allowlist(
            format!("{path}.model_allowlist"),
            &method.model_allowlist_allowed,
            &method.model_allowlist_initial,
            report,
        );
        validate_default_model(
            format!("{path}.default_model"),
            method.default_model.as_deref(),
            None,
            contract,
            report,
        );
    }
    validate_unique_strings("auth_methods.wizard_choice_id", &wizard_choice_ids, report);
}

fn validate_setup_choices(contract: &ProviderContract, report: &mut ProviderContractReport) {
    let mut choice_ids: Vec<String> = contract
        .auth_methods
        .iter()
        .filter_map(|method| method.wizard_choice_id.clone())
        .collect();

    for (index, choice) in contract.setup_choices.iter().enumerate() {
        let path = format!("setup_choices[{index}]");
        validate_non_empty(format!("{path}.choice_id"), &choice.choice_id, report);
        validate_non_empty(format!("{path}.label"), &choice.label, report);
        choice_ids.push(choice.choice_id.clone());
        if let Some(method_id) = &choice.method_id {
            validate_method_ref(format!("{path}.method_id"), method_id, contract, report);
        }
        validate_model_allowlist(
            format!("{path}.model_allowlist"),
            &choice.model_allowlist_allowed,
            &choice.model_allowlist_initial,
            report,
        );
    }

    validate_unique_strings("setup_choices.choice_id", &choice_ids, report);
    if let Some(method_id) = &contract.model_picker_method_id {
        validate_method_ref("model_picker_method_id", method_id, contract, report);
    }
}

fn validate_catalogs(contract: &ProviderContract, report: &mut ProviderContractReport) {
    let catalog_ids: Vec<String> = contract
        .model_catalogs
        .iter()
        .map(|catalog| catalog.catalog_id.clone())
        .collect();
    validate_unique_strings("model_catalogs.catalog_id", &catalog_ids, report);

    for (catalog_index, catalog) in contract.model_catalogs.iter().enumerate() {
        let path = format!("model_catalogs[{catalog_index}]");
        validate_non_empty(format!("{path}.catalog_id"), &catalog.catalog_id, report);
        if catalog.models.is_empty() && !catalog.allow_dynamic_empty_catalog {
            report.push(
                format!("{path}.models"),
                "must include at least one model or allow_dynamic_empty_catalog",
            );
        }

        let model_ids: Vec<String> = catalog
            .models
            .iter()
            .map(|model| model.model_id.clone())
            .collect();
        validate_unique_strings(format!("{path}.models.model_id"), &model_ids, report);
        for (model_index, model) in catalog.models.iter().enumerate() {
            validate_non_empty(
                format!("{path}.models[{model_index}].model_id"),
                &model.model_id,
                report,
            );
            validate_optional_non_empty(
                format!("{path}.models[{model_index}].label"),
                model.label.as_deref(),
                report,
            );
        }
    }
}

fn validate_operations(contract: &ProviderContract, report: &mut ProviderContractReport) {
    let operation_ids: Vec<String> = contract
        .operations
        .iter()
        .map(|operation| operation.operation_id.clone())
        .collect();
    validate_unique_strings("operations.operation_id", &operation_ids, report);

    for (index, operation) in contract.operations.iter().enumerate() {
        let path = format!("operations[{index}]");
        validate_non_empty(
            format!("{path}.operation_id"),
            &operation.operation_id,
            report,
        );
        validate_non_empty(
            format!("{path}.model_field"),
            &operation.model_field,
            report,
        );
        if let Some(catalog_id) = &operation.catalog_id {
            validate_non_empty(format!("{path}.catalog_id"), catalog_id, report);
            if !catalog_exists(contract, catalog_id) {
                report.push(
                    format!("{path}.catalog_id"),
                    "references an unknown catalog",
                );
            }
        }
        if operation.default_model.is_some() && operation.default_model_deferral.is_some() {
            report.push(
                format!("{path}.default_model"),
                "must not be set with default_model_deferral",
            );
        }
        if operation.requires_default_model
            && operation.default_model.is_none()
            && operation.default_model_deferral.is_none()
        {
            report.push(
                format!("{path}.default_model"),
                "must declare a default model or an explicit deferral",
            );
        }
        validate_optional_non_empty(
            format!("{path}.default_model_deferral"),
            operation.default_model_deferral.as_deref(),
            report,
        );
        validate_default_model(
            format!("{path}.default_model"),
            operation.default_model.as_deref(),
            operation.catalog_id.as_deref(),
            contract,
            report,
        );
    }
}

fn validate_base_urls(contract: &ProviderContract, report: &mut ProviderContractReport) {
    let names: Vec<String> = contract
        .base_urls
        .iter()
        .map(|base_url| base_url.name.clone())
        .collect();
    validate_unique_strings("base_urls.name", &names, report);

    for (index, base_url) in contract.base_urls.iter().enumerate() {
        let path = format!("base_urls[{index}]");
        validate_non_empty(format!("{path}.name"), &base_url.name, report);
        match Url::parse(&base_url.url) {
            Ok(url) if url.scheme() == "https" && !has_credentials(&url) => {}
            Ok(url) if url.scheme() == "http" && base_url.allow_loopback_http => {
                if !is_loopback_url(&url) || has_credentials(&url) {
                    report.push(
                        format!("{path}.url"),
                        "plain HTTP is only allowed for credential-free loopback fixture URLs",
                    );
                }
            }
            Ok(url) if has_credentials(&url) => {
                report.push(format!("{path}.url"), "must not embed URL credentials");
            }
            Ok(_) => {
                report.push(
                    format!("{path}.url"),
                    "must use HTTPS unless explicitly allowed loopback HTTP",
                );
            }
            Err(error) => {
                report.push(
                    format!("{path}.url"),
                    format!("must parse as a URL: {error}"),
                );
            }
        }
    }
}

fn validate_redaction_payloads(contract: &ProviderContract, report: &mut ProviderContractReport) {
    validate_unique_strings("secret_markers", &contract.secret_markers, report);
    for (payload_index, payload) in contract.redaction_payloads.iter().enumerate() {
        let serialized = payload.payload.to_string();
        validate_non_empty(
            format!("redaction_payloads[{payload_index}].label"),
            &payload.label,
            report,
        );
        for marker in contract
            .secret_markers
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|marker| !marker.is_empty())
        {
            if serialized.contains(marker) {
                report.push(
                    format!("redaction_payloads[{payload_index}]"),
                    format!("leaks secret marker '{marker}'"),
                );
            }
        }
    }
}

fn validate_import_side_effects(contract: &ProviderContract, report: &mut ProviderContractReport) {
    for (index, side_effects) in contract.import_side_effects.iter().enumerate() {
        let path = format!("import_side_effects[{index}]");
        validate_non_empty(format!("{path}.module_id"), &side_effects.module_id, report);
        validate_non_empty(
            format!("{path}.forbidden_surface"),
            &side_effects.forbidden_surface,
            report,
        );
        validate_non_empty(format!("{path}.why"), &side_effects.why, report);
        validate_non_empty(format!("{path}.fix_hint"), &side_effects.fix_hint, report);
        if !side_effects.observed_calls.is_empty() {
            report.push(
                format!("{path}.observed_calls"),
                format!(
                    "must be empty; {} call(s) touched {} during import",
                    side_effects.observed_calls.len(),
                    side_effects.forbidden_surface
                ),
            );
        }
    }
}

fn validate_default_model(
    path: impl Into<String>,
    model_id: Option<&str>,
    catalog_id: Option<&str>,
    contract: &ProviderContract,
    report: &mut ProviderContractReport,
) {
    let path = path.into();
    let Some(model_id) = model_id else {
        return;
    };
    validate_non_empty(&path, model_id, report);
    if model_id.trim().is_empty() {
        return;
    }
    if !model_exists(contract, model_id, catalog_id) {
        report.push(
            path,
            "default model must appear in the referenced provider model catalog",
        );
    }
}

fn validate_model_allowlist(
    path: impl Into<String>,
    allowed: &[String],
    initial: &[String],
    report: &mut ProviderContractReport,
) {
    let path = path.into();
    validate_unique_strings(format!("{path}.allowed"), allowed, report);
    validate_unique_strings(format!("{path}.initial"), initial, report);
    if allowed.is_empty() && !initial.is_empty() {
        report.push(
            format!("{path}.initial"),
            "cannot declare initial selections without allowed models",
        );
        return;
    }

    let allowed_set: HashSet<&str> = allowed.iter().map(String::as_str).collect();
    for model_id in initial {
        if !allowed_set.contains(model_id.as_str()) {
            report.push(
                format!("{path}.initial"),
                format!("initial selection '{model_id}' is not in allowed models"),
            );
        }
    }
}

fn validate_method_ref(
    path: impl Into<String>,
    method_id: &str,
    contract: &ProviderContract,
    report: &mut ProviderContractReport,
) {
    let path = path.into();
    validate_non_empty(&path, method_id, report);
    if !contract
        .auth_methods
        .iter()
        .any(|method| method.method_id == method_id)
    {
        report.push(
            path,
            format!("references unknown auth method '{method_id}'"),
        );
    }
}

fn validate_non_empty(path: impl Into<String>, value: &str, report: &mut ProviderContractReport) {
    let path = path.into();
    if value.trim().is_empty() {
        report.push(path, "must not be empty");
    } else if value.trim() != value {
        report.push(path, "must not contain leading or trailing whitespace");
    }
}

fn validate_optional_non_empty(
    path: impl Into<String>,
    value: Option<&str>,
    report: &mut ProviderContractReport,
) {
    if let Some(value) = value {
        validate_non_empty(path, value, report);
    }
}

fn validate_unique_strings(
    path: impl Into<String>,
    values: &[String],
    report: &mut ProviderContractReport,
) {
    let path = path.into();
    let mut seen = HashSet::new();
    for value in values {
        validate_non_empty(&path, value, report);
        let key = value.trim();
        if !key.is_empty() && !seen.insert(key.to_owned()) {
            report.push(&path, format!("duplicate value '{key}'"));
        }
    }
}

fn contains_string(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value == needle)
}

fn catalog_exists(contract: &ProviderContract, catalog_id: &str) -> bool {
    contract
        .model_catalogs
        .iter()
        .any(|catalog| catalog.catalog_id == catalog_id)
}

fn model_exists(contract: &ProviderContract, model_id: &str, catalog_id: Option<&str>) -> bool {
    contract.model_catalogs.iter().any(|catalog| {
        catalog_id.is_none_or(|id| id == catalog.catalog_id)
            && catalog
                .models
                .iter()
                .any(|model| model.model_id == model_id)
    })
}

fn has_credentials(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

fn is_loopback_url(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    )
}

fn is_provider_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn valid_contract() -> ProviderContract {
        let chat_schema = json!({
            "type": "object",
            "properties": {
                "model": { "type": "string", "default": "mistral-small-latest" }
            }
        });

        ProviderContract::new("mistral", "Mistral")
            .with_docs_path("/providers/mistral")
            .with_env_var("MISTRAL_API_KEY")
            .with_config_key("api_key")
            .with_auth_method(
                ProviderAuthMethodContract::new("api_key", "Mistral API key")
                    .with_env_var("MISTRAL_API_KEY")
                    .with_config_key("api_key")
                    .with_wizard_choice("mistral-api-key", "api_key")
                    .with_default_model("mistral-small-latest"),
            )
            .with_setup_choice(
                ProviderSetupChoiceContract::new("mistral-setup", "Mistral setup")
                    .with_method_id("api_key"),
            )
            .with_model_picker_method("api_key")
            .with_default_model("mistral-small-latest")
            .with_model_catalog(
                ProviderModelCatalogContract::new("chat")
                    .with_model(
                        ProviderModelContract::new("mistral-small-latest")
                            .with_label("Mistral Small Latest"),
                    )
                    .with_model(ProviderModelContract::new("mistral-embed")),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "mistral.chat.completions",
                    "chat",
                    &chat_schema,
                )
                .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "api",
                "https://api.mistral.ai/v1",
            ))
            .with_base_url(
                ProviderBaseUrlContract::new("loopback", "http://127.0.0.1:4567")
                    .allow_loopback_http(),
            )
            .with_secret_marker("sk-test-secret")
            .with_redaction_payload(ProviderRedactionPayload::new(
                "doctor",
                json!({ "auth_mode": "api_key", "api_key": "[REDACTED]" }),
            ))
    }

    fn messages(report: &ProviderContractReport) -> String {
        report.to_string()
    }

    #[test]
    fn valid_provider_contract_passes() {
        assert_provider_contract(&valid_contract());
    }

    #[test]
    fn duplicate_env_and_config_keys_fail() {
        let report = validate_provider_contract(
            &ProviderContract::new("exa", "Exa")
                .with_env_var("EXA_API_KEY")
                .with_env_var("EXA_API_KEY")
                .with_config_key("api_key")
                .with_config_key("api_key"),
        )
        .expect_err("duplicates must fail");

        let message = messages(&report);
        assert!(message.contains("env_vars"));
        assert!(message.contains("config_keys"));
        assert!(message.contains("duplicate value"));
    }

    #[test]
    fn missing_auth_labels_and_broken_wizard_refs_fail() {
        let report = validate_provider_contract(
            &ProviderContract::new("deepgram", "Deepgram")
                .with_env_var("DEEPGRAM_API_KEY")
                .with_config_key("api_key")
                .with_auth_method(
                    ProviderAuthMethodContract::new("api_key", "")
                        .with_env_var("DEEPGRAM_API_KEY")
                        .with_config_key("api_key")
                        .with_wizard_choice("deepgram-missing", "oauth"),
                )
                .with_setup_choice(
                    ProviderSetupChoiceContract::new("setup", "Setup").with_method_id("oauth"),
                ),
        )
        .expect_err("missing labels and broken references must fail");

        let message = messages(&report);
        assert!(message.contains("auth_methods[0].label"));
        assert!(message.contains("references unknown auth method 'oauth'"));
    }

    #[test]
    fn model_defaults_must_be_catalog_backed_or_deferred() {
        let missing = validate_provider_contract(
            &ProviderContract::new("openrouter", "OpenRouter")
                .with_model_catalog(
                    ProviderModelCatalogContract::new("chat")
                        .with_model(ProviderModelContract::new("openai/gpt-5.5")),
                )
                .with_operation(
                    ProviderOperationContract::new("openrouter.chat.completions")
                        .with_catalog_id("chat")
                        .with_default_model("anthropic/claude-sonnet-4.6")
                        .require_default_model(),
                ),
        )
        .expect_err("unknown model defaults must fail");
        assert!(messages(&missing).contains("default model must appear"));

        let deferred = ProviderContract::new("openrouter", "OpenRouter")
            .with_model_catalog(
                ProviderModelCatalogContract::new("chat").allow_dynamic_empty_catalog(),
            )
            .with_operation(
                ProviderOperationContract::new("openrouter.chat.completions")
                    .with_catalog_id("chat")
                    .with_default_model_deferral("live catalog determines the default")
                    .require_default_model(),
            );
        assert_provider_contract(&deferred);
    }

    #[test]
    fn operation_schema_default_is_extracted_separately_from_provider_default() {
        let schema = json!({
            "type": "object",
            "properties": {
                "model": { "type": "string", "default": "mistral-embed" }
            }
        });
        let operation = ProviderOperationContract::from_input_schema(
            "mistral.embeddings.create",
            "chat",
            &schema,
        );

        assert_eq!(operation.default_model.as_deref(), Some("mistral-embed"));

        let contract = ProviderContract::new("mistral", "Mistral")
            .with_default_model("mistral-small-latest")
            .with_model_catalog(
                ProviderModelCatalogContract::new("chat")
                    .with_model(ProviderModelContract::new("mistral-small-latest"))
                    .with_model(ProviderModelContract::new("mistral-embed")),
            )
            .with_operation(operation.require_default_model());
        assert_provider_contract(&contract);
    }

    #[test]
    fn unsafe_base_urls_fail_but_loopback_fixtures_are_explicit() {
        let report = validate_provider_contract(
            &ProviderContract::new("tavily", "Tavily")
                .with_base_url(ProviderBaseUrlContract::new("api", "http://api.tavily.com"))
                .with_base_url(ProviderBaseUrlContract::new(
                    "credentialed",
                    "https://user:secret@api.tavily.com",
                ))
                .with_base_url(
                    ProviderBaseUrlContract::new("fixture", "http://localhost:8080")
                        .allow_loopback_http(),
                ),
        )
        .expect_err("unsafe URLs must fail");

        let message = messages(&report);
        assert!(message.contains("must use HTTPS"));
        assert!(message.contains("must not embed URL credentials"));
        assert!(!message.contains("fixture"));
    }

    #[test]
    fn redaction_payloads_reject_secret_markers() {
        let report = validate_provider_contract(
            &ProviderContract::new("firecrawl", "Firecrawl")
                .with_secret_marker("fc-secret")
                .with_redaction_payload(ProviderRedactionPayload::new(
                    "doctor",
                    json!({ "authorization": "Bearer fc-secret" }),
                )),
        )
        .expect_err("secret leakage must fail");

        assert!(messages(&report).contains("leaks secret marker 'fc-secret'"));
    }

    #[test]
    fn import_time_side_effect_observations_must_be_empty() {
        let report = validate_provider_contract(
            &ProviderContract::new("anthropic", "Anthropic").with_import_side_effect(
                ProviderImportSideEffectContract::new("connectors/anthropic", "registry")
                    .with_observed_call("register_provider(anthropic)"),
            ),
        )
        .expect_err("import-time registration must fail");

        assert!(messages(&report).contains("touched registry during import"));
    }

    #[test]
    fn exact_overlap_provider_targets_are_stable_and_unique() {
        let values = EXACT_OVERLAP_PROVIDER_IDS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let mut sorted = values.clone();
        sorted.sort();
        sorted.dedup();

        assert_eq!(values.len(), 10);
        assert_eq!(values.len(), sorted.len());
        assert!(values.contains(&"openai".to_owned()));
        assert!(values.contains(&"tavily".to_owned()));
    }
}
