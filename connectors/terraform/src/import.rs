//! Terraform resource import for bringing existing infrastructure under state management.
//!
//! Import is a state-mutating operation that requires approval gating. This module
//! provides validation, injection prevention, batch handling, and audit trail for
//! controlled `terraform import` operations.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// ResourceAddress
// ---------------------------------------------------------------------------

/// A parsed and validated Terraform resource address.
///
/// Addresses follow the Terraform convention:
/// - Simple: `aws_instance.web`
/// - Module-prefixed: `module.vpc.aws_subnet.main`
/// - Nested modules: `module.vpc.module.subnets.aws_subnet.private`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceAddress {
    /// The resource type, e.g. `aws_instance`.
    pub resource_type: String,
    /// The resource name, e.g. `web`.
    pub resource_name: String,
    /// Optional module path prefix, e.g. `module.vpc`.
    pub module_path: Option<String>,
}

/// Characters allowed in identifiers (resource type, name, module segments).
const fn is_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Shell metacharacters that must never appear in resource addresses.
const FORBIDDEN_CHARS: &[char] = &[
    ';', '|', '&', '$', '`', '\\', '\n', '\r', '\'', '"', '(', ')', '{', '}', '<', '>', '!', '~',
    '#', '%', '^', '?', '*', '[', ']', '\t', '\0',
];

impl ResourceAddress {
    /// Parse a full address string like `aws_instance.web` or
    /// `module.vpc.aws_subnet.main`.
    pub fn parse(input: &str) -> Result<Self, ImportValidationError> {
        if input.is_empty() {
            return Err(ImportValidationError::EmptyAddress);
        }

        // Check for injection characters first.
        Self::check_injection(input)?;

        let parts: Vec<&str> = input.split('.').collect();

        // Must have at least type.name (2 parts).
        if parts.len() < 2 {
            return Err(ImportValidationError::InvalidAddress {
                address: input.to_string(),
                reason: "address must contain at least resource_type.resource_name".into(),
            });
        }

        // Validate all parts are non-empty and safe.
        for part in &parts {
            if part.is_empty() {
                return Err(ImportValidationError::InvalidAddress {
                    address: input.to_string(),
                    reason: "address contains empty segment (consecutive dots)".into(),
                });
            }
            if !part.chars().all(is_safe_char) {
                return Err(ImportValidationError::InvalidCharacters {
                    value: input.to_string(),
                });
            }
        }

        // Determine module path vs resource type/name.
        // Module segments come in pairs: "module", "<name>"
        // The last two segments are always resource_type.resource_name.
        let mut idx = 0;
        let mut module_segments = Vec::new();

        while idx + 2 < parts.len() {
            if parts[idx] == "module" {
                module_segments.push(format!("module.{}", parts[idx + 1]));
                idx += 2;
            } else {
                // Non-module prefix with remaining parts — invalid structure.
                return Err(ImportValidationError::InvalidAddress {
                    address: input.to_string(),
                    reason: "non-module prefix segments are not allowed before resource_type.resource_name".into(),
                });
            }
        }

        if idx + 2 != parts.len() {
            return Err(ImportValidationError::InvalidAddress {
                address: input.to_string(),
                reason: "address must end with resource_type.resource_name".into(),
            });
        }

        let resource_type = parts[idx].to_string();
        let resource_name = parts[idx + 1].to_string();

        // resource_type must not be "module".
        if resource_type == "module" {
            return Err(ImportValidationError::InvalidAddress {
                address: input.to_string(),
                reason: "resource_type cannot be 'module'".into(),
            });
        }

        let module_path = if module_segments.is_empty() {
            None
        } else {
            Some(module_segments.join("."))
        };

        Ok(Self {
            resource_type,
            resource_name,
            module_path,
        })
    }

    /// Validate this address for safety.
    pub fn validate(&self) -> Result<(), ImportValidationError> {
        let canonical = self.to_string();
        Self::check_injection(&canonical)?;

        if self.resource_type.is_empty() || self.resource_name.is_empty() {
            return Err(ImportValidationError::EmptyAddress);
        }

        if !self.resource_type.chars().all(is_safe_char) {
            return Err(ImportValidationError::InvalidCharacters {
                value: self.resource_type.clone(),
            });
        }
        if !self.resource_name.chars().all(is_safe_char) {
            return Err(ImportValidationError::InvalidCharacters {
                value: self.resource_name.clone(),
            });
        }

        if let Some(ref mp) = self.module_path {
            // Module path segments separated by dots, each segment must be safe.
            for seg in mp.split('.') {
                if seg.is_empty() {
                    return Err(ImportValidationError::InvalidAddress {
                        address: canonical,
                        reason: "module path contains empty segment".into(),
                    });
                }
                if !seg.chars().all(is_safe_char) {
                    return Err(ImportValidationError::InvalidCharacters { value: mp.clone() });
                }
            }
        }

        Ok(())
    }

    /// Check for injection characters in a string.
    fn check_injection(input: &str) -> Result<(), ImportValidationError> {
        for c in input.chars() {
            if FORBIDDEN_CHARS.contains(&c) {
                return Err(ImportValidationError::InjectionDetected {
                    value: input.to_string(),
                    character: c,
                });
            }
        }
        Ok(())
    }
}

impl fmt::Display for ResourceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref mp) = self.module_path {
            write!(f, "{}.{}.{}", mp, self.resource_type, self.resource_name)
        } else {
            write!(f, "{}.{}", self.resource_type, self.resource_name)
        }
    }
}

// ---------------------------------------------------------------------------
// ImportValidationError
// ---------------------------------------------------------------------------

/// Errors arising from import input validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportValidationError {
    /// The resource address is malformed.
    InvalidAddress { address: String, reason: String },
    /// The resource type is not in the allowed list.
    ForbiddenResourceType { resource_type: String },
    /// Potential command injection detected.
    InjectionDetected { value: String, character: char },
    /// An empty address was provided.
    EmptyAddress,
    /// An empty provider resource ID was provided.
    EmptyProviderId,
    /// Too many concurrent imports.
    ConcurrentLimitReached { limit: usize, current: usize },
    /// Invalid characters in a value.
    InvalidCharacters { value: String },
}

impl fmt::Display for ImportValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress { address, reason } => {
                write!(f, "invalid address '{address}': {reason}")
            }
            Self::ForbiddenResourceType { resource_type } => {
                write!(f, "forbidden resource type: {resource_type}")
            }
            Self::InjectionDetected { value, character } => {
                write!(
                    f,
                    "injection detected in '{value}': forbidden character '{character}'"
                )
            }
            Self::EmptyAddress => write!(f, "resource address must not be empty"),
            Self::EmptyProviderId => write!(f, "provider resource ID must not be empty"),
            Self::ConcurrentLimitReached { limit, current } => {
                write!(
                    f,
                    "concurrent import limit reached: {current}/{limit} active"
                )
            }
            Self::InvalidCharacters { value } => {
                write!(f, "invalid characters in: {value}")
            }
        }
    }
}

impl std::error::Error for ImportValidationError {}

// ---------------------------------------------------------------------------
// ImportStatus
// ---------------------------------------------------------------------------

/// Status of a resource import operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportStatus {
    /// Awaiting submission.
    Pending,
    /// Approved by an authorized party.
    Approved,
    /// Actively importing.
    Executing,
    /// Successfully imported.
    Completed,
    /// Import failed.
    Failed,
    /// Cancelled before completion.
    Cancelled,
}

impl fmt::Display for ImportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Executing => write!(f, "executing"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// ImportRequest
// ---------------------------------------------------------------------------

/// A request to import an existing infrastructure resource into Terraform state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRequest {
    /// Terraform resource address, e.g. `aws_instance.web`.
    pub resource_address: String,
    /// The provider-side resource identifier, e.g. an AWS instance ID.
    pub provider_resource_id: String,
    /// Target workspace ID.
    pub workspace_id: String,
    /// Optional approval token for gated operations.
    pub approval_token: Option<String>,
    /// When this request was created (ISO-8601).
    pub created_at: String,
}

impl ImportRequest {
    /// Validate the import request inputs.
    pub fn validate(&self) -> Result<ResourceAddress, ImportValidationError> {
        if self.resource_address.is_empty() {
            return Err(ImportValidationError::EmptyAddress);
        }
        if self.provider_resource_id.is_empty() {
            return Err(ImportValidationError::EmptyProviderId);
        }

        // Validate provider_resource_id for injection.
        ResourceAddress::check_injection(&self.provider_resource_id)?;

        // Parse and validate the address.
        let addr = ResourceAddress::parse(&self.resource_address)?;
        addr.validate()?;

        Ok(addr)
    }
}

// ---------------------------------------------------------------------------
// ImportAuditEvent
// ---------------------------------------------------------------------------

/// An audit event emitted during import processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportAuditEvent {
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// The type of event (e.g. `import_requested`, `import_approved`, `import_completed`).
    pub event_type: String,
    /// Import identifier, if assigned.
    pub import_id: Option<String>,
    /// The resource address involved.
    pub resource_address: String,
    /// Free-form details.
    pub details: String,
}

// ---------------------------------------------------------------------------
// ImportResult
// ---------------------------------------------------------------------------

/// The outcome of an import operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    /// Unique import identifier.
    pub import_id: String,
    /// The resource address that was imported.
    pub resource_address: String,
    /// The provider resource ID that was imported.
    pub provider_resource_id: String,
    /// Current status.
    pub status: ImportStatus,
    /// Workspace this import applies to.
    pub workspace_id: String,
    /// When the import started (ISO-8601).
    pub started_at: String,
    /// When the import completed, if applicable.
    pub completed_at: Option<String>,
    /// Description of state changes, if any.
    pub state_changes: Option<String>,
    /// Error message on failure.
    pub error_message: Option<String>,
    /// Ordered audit trail for this import.
    pub audit_events: Vec<ImportAuditEvent>,
}

// ---------------------------------------------------------------------------
// ImportDecision
// ---------------------------------------------------------------------------

/// The policy engine's decision on an import request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportDecision {
    /// Import is allowed without further approval.
    Allow,
    /// Import is denied.
    Deny { code: String, reason: String },
    /// Import requires explicit approval.
    NeedsApproval,
}

// ---------------------------------------------------------------------------
// ImportPolicy
// ---------------------------------------------------------------------------

/// Policy governing import operations for a workspace or organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPolicy {
    /// Whether imports require explicit approval.
    pub require_approval: bool,
    /// Resource types that are allowed for import (empty = all).
    pub allowed_resource_types: Vec<String>,
    /// Maximum number of imports per workspace.
    pub max_per_workspace: usize,
    /// Workspaces that are allowed to receive imports (empty = all).
    pub allowed_workspaces: Vec<String>,
}

impl ImportPolicy {
    /// Evaluate a request against this policy.
    pub fn check_request(&self, request: &ImportRequest) -> ImportDecision {
        // Check workspace allowlist.
        if !self.allowed_workspaces.is_empty()
            && !self.allowed_workspaces.contains(&request.workspace_id)
        {
            return ImportDecision::Deny {
                code: "WORKSPACE_NOT_ALLOWED".into(),
                reason: format!(
                    "workspace '{}' is not in the allowed list",
                    request.workspace_id
                ),
            };
        }

        // Validate the address to extract the resource type.
        let addr = match ResourceAddress::parse(&request.resource_address) {
            Ok(a) => a,
            Err(e) => {
                return ImportDecision::Deny {
                    code: "INVALID_ADDRESS".into(),
                    reason: e.to_string(),
                };
            }
        };

        // Check resource type allowlist.
        if !self.allowed_resource_types.is_empty()
            && !self.allowed_resource_types.contains(&addr.resource_type)
        {
            return ImportDecision::Deny {
                code: "RESOURCE_TYPE_NOT_ALLOWED".into(),
                reason: format!(
                    "resource type '{}' is not in the allowed list",
                    addr.resource_type
                ),
            };
        }

        // Check approval requirement.
        if self.require_approval && request.approval_token.is_none() {
            return ImportDecision::NeedsApproval;
        }

        ImportDecision::Allow
    }
}

// ---------------------------------------------------------------------------
// ImportValidator
// ---------------------------------------------------------------------------

/// Validates import requests against configurable rules and injection patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportValidator {
    /// Allowed resource types (empty = all).
    pub allowed_resource_types: Vec<String>,
    /// Regex-like patterns that are forbidden in addresses or IDs.
    pub forbidden_patterns: Vec<String>,
    /// Maximum number of concurrent imports.
    pub max_concurrent_imports: usize,
    /// Whether approval is required.
    pub require_approval: bool,
}

impl ImportValidator {
    /// Validate a single import request.
    pub fn validate_request(
        &self,
        request: &ImportRequest,
        active_count: usize,
    ) -> Result<ResourceAddress, ImportValidationError> {
        // Concurrent limit check.
        if active_count >= self.max_concurrent_imports {
            return Err(ImportValidationError::ConcurrentLimitReached {
                limit: self.max_concurrent_imports,
                current: active_count,
            });
        }

        // Basic validation.
        let addr = request.validate()?;

        // Resource type allowlist.
        self.validate_address(&addr)?;

        // Check forbidden patterns in both address and provider ID.
        self.check_forbidden_patterns(&request.resource_address)?;
        self.check_forbidden_patterns(&request.provider_resource_id)?;

        Ok(addr)
    }

    /// Validate a resource address against the allowed types.
    pub fn validate_address(&self, addr: &ResourceAddress) -> Result<(), ImportValidationError> {
        if !self.allowed_resource_types.is_empty()
            && !self.allowed_resource_types.contains(&addr.resource_type)
        {
            return Err(ImportValidationError::ForbiddenResourceType {
                resource_type: addr.resource_type.clone(),
            });
        }
        Ok(())
    }

    /// Check whether an identifier contains only safe characters.
    pub fn is_safe_identifier(value: &str) -> bool {
        if value.is_empty() {
            return false;
        }
        // Dots are allowed as separators in addresses.
        value.chars().all(|c| is_safe_char(c) || c == '.')
    }

    /// Check a value against the forbidden patterns list.
    fn check_forbidden_patterns(&self, value: &str) -> Result<(), ImportValidationError> {
        for pattern in &self.forbidden_patterns {
            if value.contains(pattern.as_str()) {
                return Err(ImportValidationError::InjectionDetected {
                    value: value.to_string(),
                    character: pattern.chars().next().unwrap_or('?'),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ImportBatch
// ---------------------------------------------------------------------------

/// A batch of import requests targeting the same workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportBatch {
    /// The individual import requests.
    pub imports: Vec<ImportRequest>,
    /// The workspace all imports target.
    pub workspace_id: String,
    /// Unique batch identifier.
    pub batch_id: String,
}

impl ImportBatch {
    /// Create a new empty batch.
    pub const fn new(workspace_id: String, batch_id: String) -> Self {
        Self {
            imports: Vec::new(),
            workspace_id,
            batch_id,
        }
    }

    /// Add an import request to the batch.
    pub fn add(&mut self, request: ImportRequest) {
        self.imports.push(request);
    }

    /// Validate all requests in the batch.
    pub fn validate_all(&self) -> Vec<Result<ResourceAddress, ImportValidationError>> {
        self.imports.iter().map(ImportRequest::validate).collect()
    }

    /// Number of imports in the batch.
    pub fn count(&self) -> usize {
        self.imports.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    fn make_request(address: &str, provider_id: &str) -> ImportRequest {
        ImportRequest {
            resource_address: address.into(),
            provider_resource_id: provider_id.into(),
            workspace_id: "ws-test-123".into(),
            approval_token: None,
            created_at: "2026-03-09T12:00:00Z".into(),
        }
    }

    fn make_approved_request(address: &str, provider_id: &str) -> ImportRequest {
        ImportRequest {
            resource_address: address.into(),
            provider_resource_id: provider_id.into(),
            workspace_id: "ws-test-123".into(),
            approval_token: Some("tok-abc".into()),
            created_at: "2026-03-09T12:00:00Z".into(),
        }
    }

    fn default_validator() -> ImportValidator {
        ImportValidator {
            allowed_resource_types: vec![],
            forbidden_patterns: vec![],
            max_concurrent_imports: 10,
            require_approval: false,
        }
    }

    fn restrictive_validator() -> ImportValidator {
        ImportValidator {
            allowed_resource_types: vec!["aws_instance".into(), "aws_s3_bucket".into()],
            forbidden_patterns: vec!["rm -rf".into(), "&&".into()],
            max_concurrent_imports: 3,
            require_approval: true,
        }
    }

    // -----------------------------------------------------------------------
    // ResourceAddress::parse — valid addresses
    // -----------------------------------------------------------------------

    #[test]
    fn parse_simple_address() {
        let addr = ResourceAddress::parse("aws_instance.web").unwrap();
        assert_eq!(addr.resource_type, "aws_instance");
        assert_eq!(addr.resource_name, "web");
        assert!(addr.module_path.is_none());
    }

    #[test]
    fn parse_module_prefixed_address() {
        let addr = ResourceAddress::parse("module.vpc.aws_subnet.main").unwrap();
        assert_eq!(addr.resource_type, "aws_subnet");
        assert_eq!(addr.resource_name, "main");
        assert_eq!(addr.module_path, Some("module.vpc".into()));
    }

    #[test]
    fn parse_nested_module_address() {
        let addr = ResourceAddress::parse("module.vpc.module.subnets.aws_subnet.private").unwrap();
        assert_eq!(addr.resource_type, "aws_subnet");
        assert_eq!(addr.resource_name, "private");
        assert_eq!(addr.module_path, Some("module.vpc.module.subnets".into()));
    }

    #[test]
    fn parse_address_with_hyphens() {
        let addr = ResourceAddress::parse("google_compute_instance.my-server").unwrap();
        assert_eq!(addr.resource_type, "google_compute_instance");
        assert_eq!(addr.resource_name, "my-server");
    }

    #[test]
    fn parse_address_with_underscores() {
        let addr = ResourceAddress::parse("azurerm_resource_group.rg_main").unwrap();
        assert_eq!(addr.resource_type, "azurerm_resource_group");
        assert_eq!(addr.resource_name, "rg_main");
    }

    #[test]
    fn parse_address_with_digits() {
        let addr = ResourceAddress::parse("aws_instance.web01").unwrap();
        assert_eq!(addr.resource_name, "web01");
    }

    #[test]
    fn parse_triple_nested_module() {
        let addr = ResourceAddress::parse("module.env.module.region.module.tier.aws_instance.app")
            .unwrap();
        assert_eq!(addr.resource_type, "aws_instance");
        assert_eq!(addr.resource_name, "app");
        assert_eq!(
            addr.module_path,
            Some("module.env.module.region.module.tier".into())
        );
    }

    // -----------------------------------------------------------------------
    // ResourceAddress::parse — invalid addresses
    // -----------------------------------------------------------------------

    #[test]
    fn parse_empty_address() {
        assert_eq!(
            ResourceAddress::parse(""),
            Err(ImportValidationError::EmptyAddress)
        );
    }

    #[test]
    fn parse_single_segment() {
        let err = ResourceAddress::parse("aws_instance").unwrap_err();
        match err {
            ImportValidationError::InvalidAddress { .. } => {}
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    #[test]
    fn parse_consecutive_dots() {
        let err = ResourceAddress::parse("aws_instance..web").unwrap_err();
        match err {
            ImportValidationError::InvalidAddress { address, .. } => {
                assert_eq!(address, "aws_instance..web");
            }
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    #[test]
    fn parse_trailing_dot() {
        let err = ResourceAddress::parse("aws_instance.web.").unwrap_err();
        match err {
            ImportValidationError::InvalidAddress { .. } => {}
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    #[test]
    fn parse_leading_dot() {
        let err = ResourceAddress::parse(".aws_instance.web").unwrap_err();
        match err {
            ImportValidationError::InvalidAddress { .. } => {}
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    #[test]
    fn parse_module_without_name() {
        // "module" alone at the end — resource_type would be "module", which is forbidden.
        let err = ResourceAddress::parse("module.vpc.module").unwrap_err();
        match err {
            ImportValidationError::InvalidAddress { .. } => {}
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    #[test]
    fn parse_odd_non_module_prefix() {
        // Three segments but first is not "module".
        let err = ResourceAddress::parse("foo.aws_instance.web").unwrap_err();
        match err {
            ImportValidationError::InvalidAddress { .. } => {}
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // ResourceAddress::to_string
    // -----------------------------------------------------------------------

    #[test]
    fn address_to_string_simple() {
        let addr = ResourceAddress {
            resource_type: "aws_instance".into(),
            resource_name: "web".into(),
            module_path: None,
        };
        assert_eq!(addr.to_string(), "aws_instance.web");
    }

    #[test]
    fn address_to_string_with_module() {
        let addr = ResourceAddress {
            resource_type: "aws_subnet".into(),
            resource_name: "main".into(),
            module_path: Some("module.vpc".into()),
        };
        assert_eq!(addr.to_string(), "module.vpc.aws_subnet.main");
    }

    #[test]
    fn parse_then_to_string_roundtrip() {
        let input = "module.vpc.aws_subnet.main";
        let addr = ResourceAddress::parse(input).unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn parse_then_to_string_simple() {
        let input = "aws_instance.web";
        let addr = ResourceAddress::parse(input).unwrap();
        assert_eq!(addr.to_string(), input);
    }

    // -----------------------------------------------------------------------
    // ResourceAddress::validate
    // -----------------------------------------------------------------------

    #[test]
    fn validate_valid_address() {
        let addr = ResourceAddress::parse("aws_instance.web").unwrap();
        assert!(addr.validate().is_ok());
    }

    #[test]
    fn validate_address_empty_type() {
        let addr = ResourceAddress {
            resource_type: String::new(),
            resource_name: "web".into(),
            module_path: None,
        };
        assert_eq!(addr.validate(), Err(ImportValidationError::EmptyAddress));
    }

    #[test]
    fn validate_address_empty_name() {
        let addr = ResourceAddress {
            resource_type: "aws_instance".into(),
            resource_name: String::new(),
            module_path: None,
        };
        assert_eq!(addr.validate(), Err(ImportValidationError::EmptyAddress));
    }

    #[test]
    fn validate_address_bad_module_path() {
        let addr = ResourceAddress {
            resource_type: "aws_instance".into(),
            resource_name: "web".into(),
            module_path: Some("module..vpc".into()),
        };
        match addr.validate() {
            Err(ImportValidationError::InvalidAddress { .. }) => {}
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Injection prevention (ResourceAddress::parse)
    // -----------------------------------------------------------------------

    #[test]
    fn inject_semicolon() {
        let err = ResourceAddress::parse("aws_instance.web; rm -rf /").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, ';');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_pipe() {
        let err = ResourceAddress::parse("aws_instance.web | cat /etc/passwd").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '|');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_ampersand() {
        let err = ResourceAddress::parse("aws_instance.web && echo hacked").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '&');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_dollar() {
        let err = ResourceAddress::parse("aws_instance.$HOME").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '$');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_backtick() {
        let err = ResourceAddress::parse("aws_instance.`whoami`").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '`');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_backslash() {
        let err = ResourceAddress::parse("aws_instance.web\\n").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '\\');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_newline() {
        let err = ResourceAddress::parse("aws_instance.web\nrm -rf /").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '\n');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_carriage_return() {
        let err = ResourceAddress::parse("aws_instance.web\rcommand").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '\r');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_single_quote() {
        let err = ResourceAddress::parse("aws_instance.web'").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '\'');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_double_quote() {
        let err = ResourceAddress::parse("aws_instance.web\"").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '"');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_parentheses() {
        let err = ResourceAddress::parse("aws_instance.web(1)").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '(');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_curly_braces() {
        let err = ResourceAddress::parse("aws_instance.web{0}").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '{');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_angle_brackets() {
        let err = ResourceAddress::parse("aws_instance.web<file").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '<');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_redirect_out() {
        let err = ResourceAddress::parse("aws_instance.web>file").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '>');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_exclamation() {
        let err = ResourceAddress::parse("aws_instance.web!").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '!');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_tilde() {
        let err = ResourceAddress::parse("aws_instance.~web").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '~');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_hash() {
        let err = ResourceAddress::parse("aws_instance.web#comment").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '#');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_percent() {
        let err = ResourceAddress::parse("aws_instance.web%s").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '%');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_caret() {
        let err = ResourceAddress::parse("aws_instance.web^1").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '^');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_question_mark() {
        let err = ResourceAddress::parse("aws_instance.web?").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '?');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_asterisk() {
        let err = ResourceAddress::parse("aws_instance.*").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '*');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_square_brackets() {
        let err = ResourceAddress::parse("aws_instance.web[0]").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '[');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_tab() {
        let err = ResourceAddress::parse("aws_instance.web\tcommand").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '\t');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn inject_null_byte() {
        let err = ResourceAddress::parse("aws_instance.web\0").unwrap_err();
        match err {
            ImportValidationError::InjectionDetected { character, .. } => {
                assert_eq!(character, '\0');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // ImportRequest::validate
    // -----------------------------------------------------------------------

    #[test]
    fn validate_valid_request() {
        let req = make_request("aws_instance.web", "i-1234567890abcdef0");
        let addr = req.validate().unwrap();
        assert_eq!(addr.resource_type, "aws_instance");
        assert_eq!(addr.resource_name, "web");
    }

    #[test]
    fn validate_request_empty_address() {
        let req = make_request("", "i-123");
        assert_eq!(req.validate(), Err(ImportValidationError::EmptyAddress));
    }

    #[test]
    fn validate_request_empty_provider_id() {
        let req = make_request("aws_instance.web", "");
        assert_eq!(req.validate(), Err(ImportValidationError::EmptyProviderId));
    }

    #[test]
    fn validate_request_injection_in_provider_id() {
        let req = make_request("aws_instance.web", "i-123; rm -rf /");
        match req.validate() {
            Err(ImportValidationError::InjectionDetected { character, .. }) => {
                assert_eq!(character, ';');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn validate_request_injection_in_address() {
        let req = make_request("aws_instance.web | cat", "i-123");
        match req.validate() {
            Err(ImportValidationError::InjectionDetected { .. }) => {}
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn validate_request_module_address() {
        let req = make_request("module.vpc.aws_subnet.main", "subnet-abc123");
        let addr = req.validate().unwrap();
        assert_eq!(addr.module_path, Some("module.vpc".into()));
    }

    #[test]
    fn validate_request_with_approval_token() {
        let req = make_approved_request("aws_instance.web", "i-123");
        assert!(req.validate().is_ok());
        assert_eq!(req.approval_token, Some("tok-abc".into()));
    }

    // -----------------------------------------------------------------------
    // ImportStatus
    // -----------------------------------------------------------------------

    #[test]
    fn import_status_display() {
        assert_eq!(ImportStatus::Pending.to_string(), "pending");
        assert_eq!(ImportStatus::Approved.to_string(), "approved");
        assert_eq!(ImportStatus::Executing.to_string(), "executing");
        assert_eq!(ImportStatus::Completed.to_string(), "completed");
        assert_eq!(ImportStatus::Failed.to_string(), "failed");
        assert_eq!(ImportStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn import_status_serde_roundtrip() {
        let statuses = vec![
            ImportStatus::Pending,
            ImportStatus::Approved,
            ImportStatus::Executing,
            ImportStatus::Completed,
            ImportStatus::Failed,
            ImportStatus::Cancelled,
        ];
        for s in statuses {
            let json = serde_json::to_string(&s).unwrap();
            let back: ImportStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn import_status_clone() {
        let s = ImportStatus::Executing;
        let cloned = s.clone();
        // Use original after clone to prove independence.
        assert_eq!(s, ImportStatus::Executing);
        assert_eq!(cloned, ImportStatus::Executing);
    }

    #[test]
    fn import_status_debug() {
        let dbg = format!("{:?}", ImportStatus::Pending);
        assert!(dbg.contains("Pending"));
    }

    // -----------------------------------------------------------------------
    // ImportResult
    // -----------------------------------------------------------------------

    #[test]
    fn import_result_serde_roundtrip() {
        let result = ImportResult {
            import_id: "imp-001".into(),
            resource_address: "aws_instance.web".into(),
            provider_resource_id: "i-abc123".into(),
            status: ImportStatus::Completed,
            workspace_id: "ws-123".into(),
            started_at: "2026-03-09T12:00:00Z".into(),
            completed_at: Some("2026-03-09T12:01:00Z".into()),
            state_changes: Some("Added aws_instance.web to state".into()),
            error_message: None,
            audit_events: vec![ImportAuditEvent {
                timestamp: "2026-03-09T12:00:00Z".into(),
                event_type: "import_completed".into(),
                import_id: Some("imp-001".into()),
                resource_address: "aws_instance.web".into(),
                details: "Import successful".into(),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ImportResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.import_id, "imp-001");
        assert_eq!(back.status, ImportStatus::Completed);
        assert_eq!(back.audit_events.len(), 1);
    }

    #[test]
    fn import_result_failed() {
        let result = ImportResult {
            import_id: "imp-002".into(),
            resource_address: "aws_instance.web".into(),
            provider_resource_id: "i-doesnotexist".into(),
            status: ImportStatus::Failed,
            workspace_id: "ws-123".into(),
            started_at: "2026-03-09T12:00:00Z".into(),
            completed_at: Some("2026-03-09T12:00:05Z".into()),
            state_changes: None,
            error_message: Some("Resource not found in provider".into()),
            audit_events: vec![],
        };
        assert_eq!(result.status, ImportStatus::Failed);
        assert!(result.error_message.is_some());
        assert!(result.state_changes.is_none());
    }

    #[test]
    fn import_result_clone() {
        let result = ImportResult {
            import_id: "imp-003".into(),
            resource_address: "aws_instance.web".into(),
            provider_resource_id: "i-abc".into(),
            status: ImportStatus::Pending,
            workspace_id: "ws-1".into(),
            started_at: "2026-03-09T12:00:00Z".into(),
            completed_at: None,
            state_changes: None,
            error_message: None,
            audit_events: vec![],
        };
        let cloned = result.clone();
        drop(result);
        assert_eq!(cloned.import_id, "imp-003");
    }

    #[test]
    fn import_result_debug() {
        let result = ImportResult {
            import_id: "imp-004".into(),
            resource_address: "aws_instance.web".into(),
            provider_resource_id: "i-abc".into(),
            status: ImportStatus::Approved,
            workspace_id: "ws-1".into(),
            started_at: "2026-03-09T12:00:00Z".into(),
            completed_at: None,
            state_changes: None,
            error_message: None,
            audit_events: vec![],
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("ImportResult"));
        assert!(dbg.contains("imp-004"));
    }

    // -----------------------------------------------------------------------
    // ImportAuditEvent
    // -----------------------------------------------------------------------

    #[test]
    fn audit_event_serde_roundtrip() {
        let evt = ImportAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            event_type: "import_requested".into(),
            import_id: Some("imp-001".into()),
            resource_address: "aws_instance.web".into(),
            details: "Requested by agent SunnyMoose".into(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: ImportAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, "import_requested");
        assert_eq!(back.import_id, Some("imp-001".into()));
    }

    #[test]
    fn audit_event_without_import_id() {
        let evt = ImportAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            event_type: "validation_failed".into(),
            import_id: None,
            resource_address: "aws_instance.bad".into(),
            details: "injection detected".into(),
        };
        assert!(evt.import_id.is_none());
    }

    #[test]
    fn audit_event_clone() {
        let evt = ImportAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            event_type: "import_approved".into(),
            import_id: Some("imp-010".into()),
            resource_address: "aws_s3_bucket.logs".into(),
            details: "Approved".into(),
        };
        let cloned = evt.clone();
        drop(evt);
        assert_eq!(cloned.import_id, Some("imp-010".into()));
    }

    #[test]
    fn audit_event_debug() {
        let evt = ImportAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            event_type: "test".into(),
            import_id: None,
            resource_address: "x.y".into(),
            details: "d".into(),
        };
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("ImportAuditEvent"));
    }

    // -----------------------------------------------------------------------
    // ImportDecision
    // -----------------------------------------------------------------------

    #[test]
    fn decision_allow_eq() {
        assert_eq!(ImportDecision::Allow, ImportDecision::Allow);
    }

    #[test]
    fn decision_needs_approval_eq() {
        assert_eq!(ImportDecision::NeedsApproval, ImportDecision::NeedsApproval);
    }

    #[test]
    fn decision_deny_eq() {
        assert_eq!(
            ImportDecision::Deny {
                code: "X".into(),
                reason: "Y".into()
            },
            ImportDecision::Deny {
                code: "X".into(),
                reason: "Y".into()
            }
        );
    }

    #[test]
    fn decision_deny_ne() {
        assert_ne!(
            ImportDecision::Deny {
                code: "A".into(),
                reason: "B".into()
            },
            ImportDecision::Deny {
                code: "C".into(),
                reason: "D".into()
            }
        );
    }

    #[test]
    fn decision_serde_roundtrip() {
        let decisions = vec![
            ImportDecision::Allow,
            ImportDecision::NeedsApproval,
            ImportDecision::Deny {
                code: "X".into(),
                reason: "blocked".into(),
            },
        ];
        for d in decisions {
            let json = serde_json::to_string(&d).unwrap();
            let back: ImportDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    #[test]
    fn decision_clone() {
        let d = ImportDecision::NeedsApproval;
        let cloned = d.clone();
        drop(d);
        assert_eq!(cloned, ImportDecision::NeedsApproval);
    }

    // -----------------------------------------------------------------------
    // ImportPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn policy_allows_all_when_empty_lists() {
        let policy = ImportPolicy {
            require_approval: false,
            allowed_resource_types: vec![],
            max_per_workspace: 100,
            allowed_workspaces: vec![],
        };
        let req = make_request("aws_instance.web", "i-123");
        assert_eq!(policy.check_request(&req), ImportDecision::Allow);
    }

    #[test]
    fn policy_denies_disallowed_workspace() {
        let policy = ImportPolicy {
            require_approval: false,
            allowed_resource_types: vec![],
            max_per_workspace: 100,
            allowed_workspaces: vec!["ws-prod".into()],
        };
        let req = make_request("aws_instance.web", "i-123");
        match policy.check_request(&req) {
            ImportDecision::Deny { code, .. } => {
                assert_eq!(code, "WORKSPACE_NOT_ALLOWED");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_allows_listed_workspace() {
        let policy = ImportPolicy {
            require_approval: false,
            allowed_resource_types: vec![],
            max_per_workspace: 100,
            allowed_workspaces: vec!["ws-test-123".into()],
        };
        let req = make_request("aws_instance.web", "i-123");
        assert_eq!(policy.check_request(&req), ImportDecision::Allow);
    }

    #[test]
    fn policy_denies_disallowed_resource_type() {
        let policy = ImportPolicy {
            require_approval: false,
            allowed_resource_types: vec!["aws_s3_bucket".into()],
            max_per_workspace: 100,
            allowed_workspaces: vec![],
        };
        let req = make_request("aws_instance.web", "i-123");
        match policy.check_request(&req) {
            ImportDecision::Deny { code, .. } => {
                assert_eq!(code, "RESOURCE_TYPE_NOT_ALLOWED");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_allows_listed_resource_type() {
        let policy = ImportPolicy {
            require_approval: false,
            allowed_resource_types: vec!["aws_instance".into()],
            max_per_workspace: 100,
            allowed_workspaces: vec![],
        };
        let req = make_request("aws_instance.web", "i-123");
        assert_eq!(policy.check_request(&req), ImportDecision::Allow);
    }

    #[test]
    fn policy_requires_approval_no_token() {
        let policy = ImportPolicy {
            require_approval: true,
            allowed_resource_types: vec![],
            max_per_workspace: 100,
            allowed_workspaces: vec![],
        };
        let req = make_request("aws_instance.web", "i-123");
        assert_eq!(policy.check_request(&req), ImportDecision::NeedsApproval);
    }

    #[test]
    fn policy_allows_with_approval_token() {
        let policy = ImportPolicy {
            require_approval: true,
            allowed_resource_types: vec![],
            max_per_workspace: 100,
            allowed_workspaces: vec![],
        };
        let req = make_approved_request("aws_instance.web", "i-123");
        assert_eq!(policy.check_request(&req), ImportDecision::Allow);
    }

    #[test]
    fn policy_denies_bad_address() {
        let policy = ImportPolicy {
            require_approval: false,
            allowed_resource_types: vec![],
            max_per_workspace: 100,
            allowed_workspaces: vec![],
        };
        let req = make_request("bad_address_no_dot", "i-123");
        match policy.check_request(&req) {
            ImportDecision::Deny { code, .. } => {
                assert_eq!(code, "INVALID_ADDRESS");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = ImportPolicy {
            require_approval: true,
            allowed_resource_types: vec!["aws_instance".into()],
            max_per_workspace: 5,
            allowed_workspaces: vec!["ws-prod".into()],
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: ImportPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.require_approval);
        assert_eq!(back.allowed_resource_types.len(), 1);
        assert_eq!(back.max_per_workspace, 5);
    }

    #[test]
    fn policy_clone() {
        let policy = ImportPolicy {
            require_approval: true,
            allowed_resource_types: vec!["aws_instance".into()],
            max_per_workspace: 5,
            allowed_workspaces: vec![],
        };
        let cloned = policy.clone();
        drop(policy);
        assert!(cloned.require_approval);
    }

    #[test]
    fn policy_debug() {
        let policy = ImportPolicy {
            require_approval: false,
            allowed_resource_types: vec![],
            max_per_workspace: 10,
            allowed_workspaces: vec![],
        };
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("ImportPolicy"));
    }

    // -----------------------------------------------------------------------
    // ImportValidator
    // -----------------------------------------------------------------------

    #[test]
    fn validator_allows_valid_request() {
        let v = default_validator();
        let req = make_request("aws_instance.web", "i-123");
        assert!(v.validate_request(&req, 0).is_ok());
    }

    #[test]
    fn validator_rejects_empty_address() {
        let v = default_validator();
        let req = make_request("", "i-123");
        assert_eq!(
            v.validate_request(&req, 0),
            Err(ImportValidationError::EmptyAddress)
        );
    }

    #[test]
    fn validator_rejects_empty_provider_id() {
        let v = default_validator();
        let req = make_request("aws_instance.web", "");
        assert_eq!(
            v.validate_request(&req, 0),
            Err(ImportValidationError::EmptyProviderId)
        );
    }

    #[test]
    fn validator_rejects_concurrent_limit() {
        let v = ImportValidator {
            max_concurrent_imports: 2,
            ..default_validator()
        };
        let req = make_request("aws_instance.web", "i-123");
        match v.validate_request(&req, 2) {
            Err(ImportValidationError::ConcurrentLimitReached { limit, current }) => {
                assert_eq!(limit, 2);
                assert_eq!(current, 2);
            }
            other => panic!("expected ConcurrentLimitReached, got {other:?}"),
        }
    }

    #[test]
    fn validator_allows_under_concurrent_limit() {
        let v = ImportValidator {
            max_concurrent_imports: 3,
            ..default_validator()
        };
        let req = make_request("aws_instance.web", "i-123");
        assert!(v.validate_request(&req, 2).is_ok());
    }

    #[test]
    fn validator_rejects_forbidden_resource_type() {
        let v = restrictive_validator();
        let req = make_request("aws_lambda_function.handler", "fn-123");
        match v.validate_request(&req, 0) {
            Err(ImportValidationError::ForbiddenResourceType { resource_type }) => {
                assert_eq!(resource_type, "aws_lambda_function");
            }
            other => panic!("expected ForbiddenResourceType, got {other:?}"),
        }
    }

    #[test]
    fn validator_allows_listed_resource_type() {
        let v = restrictive_validator();
        let req = make_request("aws_instance.web", "i-123");
        assert!(v.validate_request(&req, 0).is_ok());
    }

    #[test]
    fn validator_rejects_forbidden_pattern_in_address() {
        let v = restrictive_validator();
        // The address itself contains "&&".
        // But first the injection check in ResourceAddress::parse will catch '&'.
        let req = make_request("aws_instance.web&&echo", "i-123");
        match v.validate_request(&req, 0) {
            Err(ImportValidationError::InjectionDetected { .. }) => {}
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn validator_rejects_forbidden_pattern_in_provider_id() {
        let v = ImportValidator {
            forbidden_patterns: vec!["rm -rf".into()],
            ..default_validator()
        };
        let req = make_request("aws_instance.web", "i-123 rm -rf /tmp");
        match v.validate_request(&req, 0) {
            Err(ImportValidationError::InjectionDetected { .. }) => {}
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn validator_validate_address_empty_allowlist() {
        let v = default_validator();
        let addr = ResourceAddress::parse("random_type.name").unwrap();
        assert!(v.validate_address(&addr).is_ok());
    }

    #[test]
    fn validator_validate_address_allowed() {
        let v = restrictive_validator();
        let addr = ResourceAddress::parse("aws_instance.web").unwrap();
        assert!(v.validate_address(&addr).is_ok());
    }

    #[test]
    fn validator_validate_address_forbidden() {
        let v = restrictive_validator();
        let addr = ResourceAddress::parse("aws_vpc.main").unwrap();
        match v.validate_address(&addr) {
            Err(ImportValidationError::ForbiddenResourceType { resource_type }) => {
                assert_eq!(resource_type, "aws_vpc");
            }
            other => panic!("expected ForbiddenResourceType, got {other:?}"),
        }
    }

    #[test]
    fn is_safe_identifier_valid() {
        assert!(ImportValidator::is_safe_identifier("aws_instance"));
        assert!(ImportValidator::is_safe_identifier("my-resource"));
        assert!(ImportValidator::is_safe_identifier("abc123"));
        assert!(ImportValidator::is_safe_identifier("module.vpc"));
        assert!(ImportValidator::is_safe_identifier("a.b.c"));
    }

    #[test]
    fn is_safe_identifier_empty() {
        assert!(!ImportValidator::is_safe_identifier(""));
    }

    #[test]
    fn is_safe_identifier_with_space() {
        assert!(!ImportValidator::is_safe_identifier("aws instance"));
    }

    #[test]
    fn is_safe_identifier_with_semicolon() {
        assert!(!ImportValidator::is_safe_identifier("abc;def"));
    }

    #[test]
    fn is_safe_identifier_with_pipe() {
        assert!(!ImportValidator::is_safe_identifier("abc|def"));
    }

    #[test]
    fn is_safe_identifier_with_dollar() {
        assert!(!ImportValidator::is_safe_identifier("$HOME"));
    }

    #[test]
    fn validator_serde_roundtrip() {
        let v = restrictive_validator();
        let json = serde_json::to_string(&v).unwrap();
        let back: ImportValidator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.allowed_resource_types.len(), 2);
        assert_eq!(back.forbidden_patterns.len(), 2);
        assert_eq!(back.max_concurrent_imports, 3);
    }

    #[test]
    fn validator_clone() {
        let v = restrictive_validator();
        let cloned = v.clone();
        drop(v);
        assert!(cloned.require_approval);
    }

    #[test]
    fn validator_debug() {
        let v = default_validator();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("ImportValidator"));
    }

    // -----------------------------------------------------------------------
    // ImportBatch
    // -----------------------------------------------------------------------

    #[test]
    fn batch_new_empty() {
        let batch = ImportBatch::new("ws-1".into(), "batch-001".into());
        assert_eq!(batch.count(), 0);
        assert_eq!(batch.workspace_id, "ws-1");
        assert_eq!(batch.batch_id, "batch-001");
    }

    #[test]
    fn batch_add_and_count() {
        let mut batch = ImportBatch::new("ws-1".into(), "batch-001".into());
        batch.add(make_request("aws_instance.web", "i-123"));
        batch.add(make_request("aws_s3_bucket.logs", "my-bucket"));
        assert_eq!(batch.count(), 2);
    }

    #[test]
    fn batch_validate_all_valid() {
        let mut batch = ImportBatch::new("ws-1".into(), "batch-001".into());
        batch.add(make_request("aws_instance.web", "i-123"));
        batch.add(make_request("aws_s3_bucket.logs", "my-bucket"));
        let results = batch.validate_all();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(Result::is_ok));
    }

    #[test]
    fn batch_validate_mixed() {
        let mut batch = ImportBatch::new("ws-1".into(), "batch-001".into());
        batch.add(make_request("aws_instance.web", "i-123"));
        batch.add(make_request("", "i-456")); // invalid
        batch.add(make_request("aws_s3_bucket.logs", ""));
        let results = batch.validate_all();
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert!(results[2].is_err());
    }

    #[test]
    fn batch_validate_all_invalid() {
        let mut batch = ImportBatch::new("ws-1".into(), "batch-001".into());
        batch.add(make_request("", ""));
        batch.add(make_request("bad", "x"));
        let results = batch.validate_all();
        assert!(results.iter().all(Result::is_err));
    }

    #[test]
    fn batch_serde_roundtrip() {
        let mut batch = ImportBatch::new("ws-1".into(), "batch-001".into());
        batch.add(make_request("aws_instance.web", "i-123"));
        let json = serde_json::to_string(&batch).unwrap();
        let back: ImportBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(back.count(), 1);
        assert_eq!(back.workspace_id, "ws-1");
        assert_eq!(back.batch_id, "batch-001");
    }

    #[test]
    fn batch_clone() {
        let mut batch = ImportBatch::new("ws-1".into(), "batch-001".into());
        batch.add(make_request("aws_instance.web", "i-123"));
        let cloned = batch.clone();
        drop(batch);
        assert_eq!(cloned.count(), 1);
    }

    #[test]
    fn batch_debug() {
        let batch = ImportBatch::new("ws-1".into(), "batch-001".into());
        let dbg = format!("{batch:?}");
        assert!(dbg.contains("ImportBatch"));
    }

    // -----------------------------------------------------------------------
    // ImportValidationError Display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_empty_address() {
        assert_eq!(
            ImportValidationError::EmptyAddress.to_string(),
            "resource address must not be empty"
        );
    }

    #[test]
    fn error_display_empty_provider_id() {
        assert_eq!(
            ImportValidationError::EmptyProviderId.to_string(),
            "provider resource ID must not be empty"
        );
    }

    #[test]
    fn error_display_invalid_address() {
        let err = ImportValidationError::InvalidAddress {
            address: "bad".into(),
            reason: "too short".into(),
        };
        let s = err.to_string();
        assert!(s.contains("bad"));
        assert!(s.contains("too short"));
    }

    #[test]
    fn error_display_forbidden_type() {
        let err = ImportValidationError::ForbiddenResourceType {
            resource_type: "aws_vpc".into(),
        };
        let s = err.to_string();
        assert!(s.contains("aws_vpc"));
    }

    #[test]
    fn error_display_injection() {
        let err = ImportValidationError::InjectionDetected {
            value: "bad;input".into(),
            character: ';',
        };
        let s = err.to_string();
        assert!(s.contains("injection"));
        assert!(s.contains(';'));
    }

    #[test]
    fn error_display_concurrent_limit() {
        let err = ImportValidationError::ConcurrentLimitReached {
            limit: 5,
            current: 5,
        };
        let s = err.to_string();
        assert!(s.contains("5/5"));
    }

    #[test]
    fn error_display_invalid_chars() {
        let err = ImportValidationError::InvalidCharacters {
            value: "abc def".into(),
        };
        let s = err.to_string();
        assert!(s.contains("abc def"));
    }

    // -----------------------------------------------------------------------
    // ImportValidationError traits
    // -----------------------------------------------------------------------

    #[test]
    fn validation_error_clone() {
        let err = ImportValidationError::EmptyAddress;
        let cloned = err.clone();
        drop(err);
        assert_eq!(cloned, ImportValidationError::EmptyAddress);
    }

    #[test]
    fn validation_error_eq() {
        assert_eq!(
            ImportValidationError::EmptyAddress,
            ImportValidationError::EmptyAddress
        );
        assert_eq!(
            ImportValidationError::EmptyProviderId,
            ImportValidationError::EmptyProviderId
        );
        assert_ne!(
            ImportValidationError::EmptyAddress,
            ImportValidationError::EmptyProviderId
        );
    }

    #[test]
    fn validation_error_debug() {
        let err = ImportValidationError::EmptyAddress;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("EmptyAddress"));
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let errors = vec![
            ImportValidationError::EmptyAddress,
            ImportValidationError::EmptyProviderId,
            ImportValidationError::InvalidAddress {
                address: "x".into(),
                reason: "y".into(),
            },
            ImportValidationError::ForbiddenResourceType {
                resource_type: "z".into(),
            },
            ImportValidationError::InjectionDetected {
                value: "a;b".into(),
                character: ';',
            },
            ImportValidationError::ConcurrentLimitReached {
                limit: 5,
                current: 5,
            },
            ImportValidationError::InvalidCharacters {
                value: "bad".into(),
            },
        ];
        for e in errors {
            let json = serde_json::to_string(&e).unwrap();
            let back: ImportValidationError = serde_json::from_str(&json).unwrap();
            assert_eq!(e, back);
        }
    }

    #[test]
    fn validation_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ImportValidationError::EmptyAddress);
        assert!(!err.to_string().is_empty());
    }

    // -----------------------------------------------------------------------
    // ImportRequest traits
    // -----------------------------------------------------------------------

    #[test]
    fn import_request_serde_roundtrip() {
        let req = make_approved_request("aws_instance.web", "i-123");
        let json = serde_json::to_string(&req).unwrap();
        let back: ImportRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.resource_address, "aws_instance.web");
        assert_eq!(back.provider_resource_id, "i-123");
        assert_eq!(back.approval_token, Some("tok-abc".into()));
    }

    #[test]
    fn import_request_clone() {
        let req = make_request("aws_instance.web", "i-123");
        let cloned = req.clone();
        drop(req);
        assert_eq!(cloned.resource_address, "aws_instance.web");
    }

    #[test]
    fn import_request_debug() {
        let req = make_request("aws_instance.web", "i-123");
        let dbg = format!("{req:?}");
        assert!(dbg.contains("ImportRequest"));
    }

    // -----------------------------------------------------------------------
    // ResourceAddress traits
    // -----------------------------------------------------------------------

    #[test]
    fn resource_address_eq() {
        let a = ResourceAddress::parse("aws_instance.web").unwrap();
        let b = ResourceAddress::parse("aws_instance.web").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn resource_address_ne() {
        let a = ResourceAddress::parse("aws_instance.web").unwrap();
        let b = ResourceAddress::parse("aws_instance.app").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn resource_address_serde_roundtrip() {
        let addr = ResourceAddress::parse("module.vpc.aws_subnet.main").unwrap();
        let json = serde_json::to_string(&addr).unwrap();
        let back: ResourceAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, back);
    }

    #[test]
    fn resource_address_clone() {
        let addr = ResourceAddress::parse("aws_instance.web").unwrap();
        let cloned = addr.clone();
        drop(addr);
        assert_eq!(cloned.resource_type, "aws_instance");
    }

    #[test]
    fn resource_address_debug() {
        let addr = ResourceAddress::parse("aws_instance.web").unwrap();
        let dbg = format!("{addr:?}");
        assert!(dbg.contains("ResourceAddress"));
        assert!(dbg.contains("aws_instance"));
    }

    // -----------------------------------------------------------------------
    // Injection in provider_resource_id
    // -----------------------------------------------------------------------

    #[test]
    fn provider_id_injection_pipe() {
        let req = make_request("aws_instance.web", "i-123 | cat /etc/shadow");
        match req.validate() {
            Err(ImportValidationError::InjectionDetected { character, .. }) => {
                assert_eq!(character, '|');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn provider_id_injection_backtick() {
        let req = make_request("aws_instance.web", "`whoami`");
        match req.validate() {
            Err(ImportValidationError::InjectionDetected { character, .. }) => {
                assert_eq!(character, '`');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn provider_id_injection_dollar_subshell() {
        let req = make_request("aws_instance.web", "$(id)");
        match req.validate() {
            Err(ImportValidationError::InjectionDetected { character, .. }) => {
                assert_eq!(character, '$');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn provider_id_injection_newline() {
        let req = make_request("aws_instance.web", "i-123\nmalicious");
        match req.validate() {
            Err(ImportValidationError::InjectionDetected { character, .. }) => {
                assert_eq!(character, '\n');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn provider_id_injection_null_byte() {
        let req = make_request("aws_instance.web", "i-123\0evil");
        match req.validate() {
            Err(ImportValidationError::InjectionDetected { character, .. }) => {
                assert_eq!(character, '\0');
            }
            other => panic!("expected InjectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn provider_id_valid_aws_instance_id() {
        let req = make_request("aws_instance.web", "i-1234567890abcdef0");
        assert!(req.validate().is_ok());
    }

    #[test]
    fn provider_id_valid_arn() {
        // ARNs contain colons and slashes — those are not forbidden.
        let req = make_request("aws_iam_role.admin", "arn:aws:iam::123456789012:role/admin");
        assert!(req.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn address_two_character_segments() {
        let addr = ResourceAddress::parse("ab.cd").unwrap();
        assert_eq!(addr.resource_type, "ab");
        assert_eq!(addr.resource_name, "cd");
    }

    #[test]
    fn address_single_char_segments() {
        let addr = ResourceAddress::parse("a.b").unwrap();
        assert_eq!(addr.resource_type, "a");
        assert_eq!(addr.resource_name, "b");
    }

    #[test]
    fn address_long_module_chain() {
        let input = "module.a.module.b.module.c.module.d.aws_instance.deep";
        let addr = ResourceAddress::parse(input).unwrap();
        assert_eq!(addr.resource_type, "aws_instance");
        assert_eq!(addr.resource_name, "deep");
        assert_eq!(
            addr.module_path,
            Some("module.a.module.b.module.c.module.d".into())
        );
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn validator_concurrent_limit_at_boundary() {
        let v = ImportValidator {
            max_concurrent_imports: 1,
            ..default_validator()
        };
        let req = make_request("aws_instance.web", "i-123");
        // At the limit.
        assert!(v.validate_request(&req, 1).is_err());
        // Below the limit.
        assert!(v.validate_request(&req, 0).is_ok());
    }

    #[test]
    fn batch_validate_preserves_order() {
        let mut batch = ImportBatch::new("ws-1".into(), "batch-001".into());
        batch.add(make_request("aws_instance.a", "id-a"));
        batch.add(make_request("", "id-b")); // invalid
        batch.add(make_request("aws_instance.c", "id-c"));
        let results = batch.validate_all();
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert!(results[2].is_ok());
        assert_eq!(results[0].as_ref().unwrap().resource_name, "a");
        assert_eq!(results[2].as_ref().unwrap().resource_name, "c");
    }

    #[test]
    fn policy_check_with_injection_in_address() {
        let policy = ImportPolicy {
            require_approval: false,
            allowed_resource_types: vec![],
            max_per_workspace: 100,
            allowed_workspaces: vec![],
        };
        let req = make_request("aws_instance.web;rm", "i-123");
        match policy.check_request(&req) {
            ImportDecision::Deny { code, .. } => {
                assert_eq!(code, "INVALID_ADDRESS");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_workspace_check_comes_first() {
        // Even with bad resource type, workspace check should fire first.
        let policy = ImportPolicy {
            require_approval: false,
            allowed_resource_types: vec!["aws_instance".into()],
            max_per_workspace: 100,
            allowed_workspaces: vec!["ws-allowed".into()],
        };
        let req = make_request("aws_vpc.main", "vpc-123");
        match policy.check_request(&req) {
            ImportDecision::Deny { code, .. } => {
                assert_eq!(code, "WORKSPACE_NOT_ALLOWED");
            }
            other => panic!("expected Deny WORKSPACE_NOT_ALLOWED, got {other:?}"),
        }
    }

    #[test]
    fn import_result_with_multiple_audit_events() {
        let result = ImportResult {
            import_id: "imp-005".into(),
            resource_address: "aws_instance.web".into(),
            provider_resource_id: "i-abc".into(),
            status: ImportStatus::Completed,
            workspace_id: "ws-1".into(),
            started_at: "2026-03-09T12:00:00Z".into(),
            completed_at: Some("2026-03-09T12:01:00Z".into()),
            state_changes: Some("resource added".into()),
            error_message: None,
            audit_events: vec![
                ImportAuditEvent {
                    timestamp: "2026-03-09T12:00:00Z".into(),
                    event_type: "import_requested".into(),
                    import_id: Some("imp-005".into()),
                    resource_address: "aws_instance.web".into(),
                    details: "Requested".into(),
                },
                ImportAuditEvent {
                    timestamp: "2026-03-09T12:00:01Z".into(),
                    event_type: "import_approved".into(),
                    import_id: Some("imp-005".into()),
                    resource_address: "aws_instance.web".into(),
                    details: "Approved by admin".into(),
                },
                ImportAuditEvent {
                    timestamp: "2026-03-09T12:01:00Z".into(),
                    event_type: "import_completed".into(),
                    import_id: Some("imp-005".into()),
                    resource_address: "aws_instance.web".into(),
                    details: "Import successful".into(),
                },
            ],
        };
        assert_eq!(result.audit_events.len(), 3);
        assert_eq!(result.audit_events[0].event_type, "import_requested");
        assert_eq!(result.audit_events[2].event_type, "import_completed");
    }

    #[test]
    fn batch_multiple_workspaces_mismatch() {
        // Batch has workspace ws-1, but request has ws-test-123.
        // ImportBatch doesn't enforce matching — that's a policy concern.
        let mut batch = ImportBatch::new("ws-other".into(), "batch-002".into());
        batch.add(make_request("aws_instance.web", "i-123"));
        assert_eq!(batch.count(), 1);
        // Validation still works on individual requests.
        let results = batch.validate_all();
        assert!(results[0].is_ok());
    }

    #[test]
    fn address_with_numeric_only_name() {
        let addr = ResourceAddress::parse("aws_instance.123").unwrap();
        assert_eq!(addr.resource_name, "123");
    }

    #[test]
    fn address_with_numeric_only_type() {
        let addr = ResourceAddress::parse("123.abc").unwrap();
        assert_eq!(addr.resource_type, "123");
    }

    #[test]
    fn safe_identifier_with_only_dots() {
        assert!(ImportValidator::is_safe_identifier("..."));
    }

    #[test]
    fn safe_identifier_unicode() {
        assert!(!ImportValidator::is_safe_identifier("\u{00e9}clair"));
    }

    #[test]
    fn safe_identifier_mixed() {
        assert!(ImportValidator::is_safe_identifier("a_b-c.d"));
    }

    #[test]
    fn import_request_no_approval_token() {
        let req = make_request("aws_instance.web", "i-123");
        assert!(req.approval_token.is_none());
    }

    #[test]
    fn validator_zero_max_concurrent() {
        let v = ImportValidator {
            max_concurrent_imports: 0,
            ..default_validator()
        };
        let req = make_request("aws_instance.web", "i-123");
        match v.validate_request(&req, 0) {
            Err(ImportValidationError::ConcurrentLimitReached { limit, current }) => {
                assert_eq!(limit, 0);
                assert_eq!(current, 0);
            }
            other => panic!("expected ConcurrentLimitReached, got {other:?}"),
        }
    }

    #[test]
    fn resource_address_validate_with_module_path() {
        let addr = ResourceAddress {
            resource_type: "aws_instance".into(),
            resource_name: "web".into(),
            module_path: Some("module.vpc".into()),
        };
        assert!(addr.validate().is_ok());
    }

    #[test]
    fn resource_address_validate_bad_chars_in_type() {
        let addr = ResourceAddress {
            resource_type: "aws instance".into(),
            resource_name: "web".into(),
            module_path: None,
        };
        match addr.validate() {
            Err(ImportValidationError::InvalidCharacters { .. }) => {}
            other => panic!("expected InvalidCharacters, got {other:?}"),
        }
    }

    #[test]
    fn resource_address_validate_bad_chars_in_name() {
        let addr = ResourceAddress {
            resource_type: "aws_instance".into(),
            resource_name: "web server".into(),
            module_path: None,
        };
        match addr.validate() {
            Err(ImportValidationError::InvalidCharacters { .. }) => {}
            other => panic!("expected InvalidCharacters, got {other:?}"),
        }
    }

    #[test]
    fn resource_address_validate_bad_chars_in_module_path() {
        let addr = ResourceAddress {
            resource_type: "aws_instance".into(),
            resource_name: "web".into(),
            module_path: Some("module.v p c".into()),
        };
        match addr.validate() {
            Err(ImportValidationError::InvalidCharacters { .. }) => {}
            other => panic!("expected InvalidCharacters, got {other:?}"),
        }
    }
}
