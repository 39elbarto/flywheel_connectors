//! Per-zone MCP tool scoping and capability enforcement.
//!
//! Ensures MCP server mode respects FCP zone boundaries: agents only see and
//! invoke tools they are authorized to use in their current zone. Provides
//! zone-aware tool filtering, capability token validation, and structured
//! error responses for zone violations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Zone Types ────────────────────────────────────────────────────

/// An FCP zone identifier (e.g., `"z:work"`, `"z:private"`, `"z:public"`).
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct ZoneId(String);

impl ZoneId {
    /// Create a zone ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The zone string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the public zone.
    pub fn is_public(&self) -> bool {
        self.0 == "z:public"
    }

    /// Whether this is a well-known zone (starts with `"z:"`).
    pub fn is_well_known(&self) -> bool {
        self.0.starts_with("z:")
    }
}

impl fmt::Display for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ZoneId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// A capability token that grants access to operations within a zone.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CapabilityToken {
    /// Zone this token grants access to.
    pub zone: ZoneId,
    /// Agent or principal this token is for.
    pub principal: String,
    /// Connectors authorized in this zone (empty = all).
    pub allowed_connectors: BTreeSet<String>,
    /// Operations explicitly denied (overrides allowed connectors).
    pub denied_operations: BTreeSet<String>,
    /// Token creation timestamp (Unix seconds).
    pub issued_at: u64,
    /// Token expiry (Unix seconds, 0 = no expiry).
    pub expires_at: u64,
}

impl CapabilityToken {
    /// Create a new token for a zone and principal.
    pub fn new(zone: ZoneId, principal: impl Into<String>) -> Self {
        Self {
            zone,
            principal: principal.into(),
            allowed_connectors: BTreeSet::new(),
            denied_operations: BTreeSet::new(),
            issued_at: 0,
            expires_at: 0,
        }
    }

    /// Builder: allow a connector.
    pub fn with_connector(mut self, connector: impl Into<String>) -> Self {
        self.allowed_connectors.insert(connector.into());
        self
    }

    /// Builder: deny an operation.
    pub fn with_denied_operation(mut self, op: impl Into<String>) -> Self {
        self.denied_operations.insert(op.into());
        self
    }

    /// Builder: set expiry.
    pub const fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Whether the token has expired (given current time in Unix seconds).
    pub const fn is_expired(&self, now: u64) -> bool {
        self.expires_at > 0 && now > self.expires_at
    }

    /// Whether a connector is allowed by this token.
    pub fn allows_connector(&self, connector: &str) -> bool {
        self.allowed_connectors.is_empty() || self.allowed_connectors.contains(connector)
    }

    /// Whether a specific operation is denied.
    pub fn is_operation_denied(&self, op: &str) -> bool {
        self.denied_operations.contains(op)
    }
}

// ── Tool Entry ────────────────────────────────────────────────────

/// A tool entry in the MCP server with zone metadata.
#[derive(Clone, Debug, Serialize)]
pub struct ZoneScopedTool {
    /// Tool name (e.g., `"github.create_issue"`).
    pub name: String,
    /// Connector that provides this tool.
    pub connector: String,
    /// Operation name.
    pub operation: String,
    /// Zones this tool is available in.
    pub zones: BTreeSet<ZoneId>,
    /// Description.
    pub description: String,
}

impl ZoneScopedTool {
    /// Create a new tool entry.
    pub fn new(
        connector: impl Into<String>,
        operation: impl Into<String>,
    ) -> Self {
        let connector = connector.into();
        let operation = operation.into();
        let name = format!("{connector}.{operation}");
        Self {
            name,
            connector,
            operation,
            zones: BTreeSet::new(),
            description: String::new(),
        }
    }

    /// Builder: add a zone.
    pub fn with_zone(mut self, zone: ZoneId) -> Self {
        self.zones.insert(zone);
        self
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Whether this tool is available in the given zone.
    pub fn available_in(&self, zone: &ZoneId) -> bool {
        self.zones.contains(zone)
    }
}

// ── Zone Violation ────────────────────────────────────────────────

/// Reason for a zone access violation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationReason {
    /// Connector not authorized in this zone.
    ConnectorNotInZone,
    /// Operation explicitly denied.
    OperationDenied,
    /// Token expired.
    TokenExpired,
    /// No token provided.
    NoToken,
    /// Zone not recognized.
    UnknownZone,
}

impl fmt::Display for ViolationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectorNotInZone => f.write_str("connector not authorized in zone"),
            Self::OperationDenied => f.write_str("operation explicitly denied"),
            Self::TokenExpired => f.write_str("capability token expired"),
            Self::NoToken => f.write_str("no capability token provided"),
            Self::UnknownZone => f.write_str("zone not recognized"),
        }
    }
}

/// Structured error for zone violations (MCP error response).
#[derive(Clone, Debug, Serialize)]
pub struct ZoneViolation {
    /// Tool that was requested.
    pub tool: String,
    /// Zone the agent is operating in.
    pub zone: ZoneId,
    /// Why the access was denied.
    pub reason: ViolationReason,
    /// Human-readable explanation.
    pub message: String,
    /// Suggested zones where this tool is available.
    pub available_in: Vec<ZoneId>,
}

impl ZoneViolation {
    /// Create a new violation.
    pub fn new(
        tool: impl Into<String>,
        zone: ZoneId,
        reason: ViolationReason,
    ) -> Self {
        let tool = tool.into();
        let message = format!("Tool '{}' not available in zone '{}': {}", tool, zone, reason);
        Self {
            tool,
            zone,
            reason,
            message,
            available_in: Vec::new(),
        }
    }

    /// Builder: add zones where the tool is available.
    pub fn with_available_in(mut self, zones: Vec<ZoneId>) -> Self {
        self.available_in = zones;
        self
    }
}

impl fmt::Display for ZoneViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

// ── Zone Registry ─────────────────────────────────────────────────

/// Registry of tools and their zone assignments.
#[derive(Clone, Debug, Default)]
pub struct ZoneRegistry {
    /// All registered tools.
    tools: Vec<ZoneScopedTool>,
    /// Known zones.
    zones: BTreeSet<ZoneId>,
}

impl ZoneRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            tools: Vec::new(),
            zones: BTreeSet::new(),
        }
    }

    /// Register a tool.
    pub fn register_tool(&mut self, tool: ZoneScopedTool) {
        for zone in &tool.zones {
            self.zones.insert(zone.clone());
        }
        self.tools.push(tool);
    }

    /// Get all tools available in a zone.
    pub fn tools_in_zone(&self, zone: &ZoneId) -> Vec<&ZoneScopedTool> {
        self.tools
            .iter()
            .filter(|t| t.available_in(zone))
            .collect()
    }

    /// Get tools for a specific connector in a zone.
    pub fn tools_for_connector_in_zone(
        &self,
        connector: &str,
        zone: &ZoneId,
    ) -> Vec<&ZoneScopedTool> {
        self.tools
            .iter()
            .filter(|t| t.connector == connector && t.available_in(zone))
            .collect()
    }

    /// Check if a zone is known.
    pub fn has_zone(&self, zone: &ZoneId) -> bool {
        self.zones.contains(zone)
    }

    /// All known zones.
    pub fn known_zones(&self) -> &BTreeSet<ZoneId> {
        &self.zones
    }

    /// Total tool count.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Tool count in a specific zone.
    pub fn tool_count_in_zone(&self, zone: &ZoneId) -> usize {
        self.tools_in_zone(zone).len()
    }

    /// All unique connectors in a zone.
    pub fn connectors_in_zone(&self, zone: &ZoneId) -> BTreeSet<String> {
        self.tools_in_zone(zone)
            .iter()
            .map(|t| t.connector.clone())
            .collect()
    }
}

// ── Validation ────────────────────────────────────────────────────

/// Validate a tool call against zone capability.
pub fn validate_tool_call(
    registry: &ZoneRegistry,
    tool_name: &str,
    zone: &ZoneId,
    token: Option<&CapabilityToken>,
) -> Result<(), ZoneViolation> {
    // Must have a token
    let Some(token) = token else {
        return Err(ZoneViolation::new(tool_name, zone.clone(), ViolationReason::NoToken));
    };

    // Token must match zone
    if token.zone != *zone {
        return Err(ZoneViolation::new(tool_name, zone.clone(), ViolationReason::UnknownZone));
    }

    // Token must not be expired
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if token.is_expired(now) {
        return Err(ZoneViolation::new(tool_name, zone.clone(), ViolationReason::TokenExpired));
    }

    // Find the tool
    let tool = registry
        .tools
        .iter()
        .find(|t| t.name == tool_name);

    let Some(tool) = tool else {
        return Err(ZoneViolation::new(tool_name, zone.clone(), ViolationReason::ConnectorNotInZone));
    };

    // Tool must be available in zone
    if !tool.available_in(zone) {
        let available: Vec<ZoneId> = tool.zones.iter().cloned().collect();
        return Err(
            ZoneViolation::new(tool_name, zone.clone(), ViolationReason::ConnectorNotInZone)
                .with_available_in(available),
        );
    }

    // Connector must be allowed by token
    if !token.allows_connector(&tool.connector) {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::ConnectorNotInZone,
        ));
    }

    // Operation must not be denied
    if token.is_operation_denied(&tool.operation) {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::OperationDenied,
        ));
    }

    Ok(())
}

/// Filter a tool list based on zone and capability token.
pub fn filter_tools_for_zone<'a>(
    tools: &'a [ZoneScopedTool],
    zone: &ZoneId,
    token: &CapabilityToken,
) -> Vec<&'a ZoneScopedTool> {
    tools
        .iter()
        .filter(|t| {
            t.available_in(zone)
                && token.allows_connector(&t.connector)
                && !token.is_operation_denied(&t.operation)
        })
        .collect()
}

// ── Display helpers ───────────────────────────────────────────────

/// Format zone tool listing for TOON display.
pub fn format_zone_tools(zone: &ZoneId, tools: &[&ZoneScopedTool]) -> String {
    let mut lines = vec![format!("Zone: {} ({} tools)", zone, tools.len())];
    let mut by_connector: BTreeMap<&str, Vec<&ZoneScopedTool>> = BTreeMap::new();
    for tool in tools {
        by_connector
            .entry(&tool.connector)
            .or_default()
            .push(tool);
    }
    for (connector, conn_tools) in &by_connector {
        lines.push(format!("  {connector}:"));
        for t in conn_tools {
            lines.push(format!("    - {}", t.operation));
        }
    }
    lines.join("\n")
}

/// Format a zone violation for TOON display.
pub fn format_violation(violation: &ZoneViolation) -> String {
    let mut output = format!("✗ {}", violation.message);
    if !violation.available_in.is_empty() {
        let zones: Vec<&str> = violation.available_in.iter().map(ZoneId::as_str).collect();
        use std::fmt::Write;
        let _ = write!(output, "\n  Available in: {}", zones.join(", "));
    }
    output
}

/// Parse a zone string, adding `z:` prefix if missing.
pub fn parse_zone(s: &str) -> ZoneId {
    let s = s.trim();
    if s.starts_with("z:") {
        ZoneId::new(s)
    } else {
        ZoneId::new(format!("z:{s}"))
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zone_work() -> ZoneId {
        ZoneId::new("z:work")
    }

    fn zone_public() -> ZoneId {
        ZoneId::new("z:public")
    }

    fn zone_private() -> ZoneId {
        ZoneId::new("z:private")
    }

    fn sample_token(zone: ZoneId) -> CapabilityToken {
        CapabilityToken::new(zone, "agent-1")
    }

    fn sample_registry() -> ZoneRegistry {
        let mut reg = ZoneRegistry::new();
        reg.register_tool(
            ZoneScopedTool::new("github", "create_issue")
                .with_zone(zone_work())
                .with_zone(zone_public()),
        );
        reg.register_tool(
            ZoneScopedTool::new("github", "list_repos")
                .with_zone(zone_work())
                .with_zone(zone_public()),
        );
        reg.register_tool(
            ZoneScopedTool::new("slack", "send_message")
                .with_zone(zone_work()),
        );
        reg.register_tool(
            ZoneScopedTool::new("vault", "get_secret")
                .with_zone(zone_private()),
        );
        reg
    }

    // ── ZoneId ────────────────────────────────────────────────────

    #[test]
    fn zone_id_basic() {
        let z = ZoneId::new("z:work");
        assert_eq!(z.as_str(), "z:work");
        assert_eq!(z.to_string(), "z:work");
    }

    #[test]
    fn zone_id_public() {
        assert!(ZoneId::new("z:public").is_public());
        assert!(!ZoneId::new("z:work").is_public());
    }

    #[test]
    fn zone_id_well_known() {
        assert!(ZoneId::new("z:work").is_well_known());
        assert!(!ZoneId::new("custom").is_well_known());
    }

    #[test]
    fn zone_id_from_str() {
        let z: ZoneId = "z:test".into();
        assert_eq!(z.as_str(), "z:test");
    }

    #[test]
    fn zone_id_equality() {
        assert_eq!(ZoneId::new("z:work"), ZoneId::new("z:work"));
        assert_ne!(ZoneId::new("z:work"), ZoneId::new("z:public"));
    }

    #[test]
    fn zone_id_ordering() {
        assert!(ZoneId::new("z:a") < ZoneId::new("z:b"));
    }

    #[test]
    fn zone_id_serializes() {
        let z = ZoneId::new("z:work");
        let json = serde_json::to_value(&z).unwrap();
        assert_eq!(json, "z:work");
    }

    // ── CapabilityToken ───────────────────────────────────────────

    #[test]
    fn token_basic() {
        let t = CapabilityToken::new(zone_work(), "agent-1");
        assert_eq!(t.zone, zone_work());
        assert_eq!(t.principal, "agent-1");
        assert!(t.allowed_connectors.is_empty());
    }

    #[test]
    fn token_allows_all_connectors_when_empty() {
        let t = sample_token(zone_work());
        assert!(t.allows_connector("github"));
        assert!(t.allows_connector("slack"));
    }

    #[test]
    fn token_restricts_connectors() {
        let t = sample_token(zone_work()).with_connector("github");
        assert!(t.allows_connector("github"));
        assert!(!t.allows_connector("slack"));
    }

    #[test]
    fn token_denied_operations() {
        let t = sample_token(zone_work())
            .with_denied_operation("delete_repo");
        assert!(t.is_operation_denied("delete_repo"));
        assert!(!t.is_operation_denied("create_issue"));
    }

    #[test]
    fn token_not_expired() {
        let t = sample_token(zone_work()).with_expiry(u64::MAX);
        assert!(!t.is_expired(1000));
    }

    #[test]
    fn token_expired() {
        let t = sample_token(zone_work()).with_expiry(100);
        assert!(t.is_expired(200));
    }

    #[test]
    fn token_no_expiry() {
        let t = sample_token(zone_work());
        assert!(!t.is_expired(u64::MAX));
    }

    #[test]
    fn token_serializes() {
        let t = sample_token(zone_work());
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["zone"], "z:work");
        assert_eq!(json["principal"], "agent-1");
    }

    // ── ZoneScopedTool ────────────────────────────────────────────

    #[test]
    fn tool_basic() {
        let t = ZoneScopedTool::new("github", "create_issue");
        assert_eq!(t.name, "github.create_issue");
        assert_eq!(t.connector, "github");
        assert_eq!(t.operation, "create_issue");
    }

    #[test]
    fn tool_with_zones() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_zone(zone_work())
            .with_zone(zone_public());
        assert!(t.available_in(&zone_work()));
        assert!(t.available_in(&zone_public()));
        assert!(!t.available_in(&zone_private()));
    }

    #[test]
    fn tool_with_description() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_description("Create a GitHub issue");
        assert_eq!(t.description, "Create a GitHub issue");
    }

    #[test]
    fn tool_serializes() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_zone(zone_work());
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["name"], "github.create_issue");
    }

    // ── ViolationReason ───────────────────────────────────────────

    #[test]
    fn violation_reason_display() {
        assert_eq!(
            ViolationReason::ConnectorNotInZone.to_string(),
            "connector not authorized in zone"
        );
        assert_eq!(
            ViolationReason::OperationDenied.to_string(),
            "operation explicitly denied"
        );
        assert_eq!(
            ViolationReason::TokenExpired.to_string(),
            "capability token expired"
        );
        assert_eq!(
            ViolationReason::NoToken.to_string(),
            "no capability token provided"
        );
    }

    #[test]
    fn violation_reason_serializes() {
        let json = serde_json::to_value(ViolationReason::NoToken).unwrap();
        assert_eq!(json, "no_token");
    }

    // ── ZoneViolation ─────────────────────────────────────────────

    #[test]
    fn violation_basic() {
        let v = ZoneViolation::new("github.create_issue", zone_public(), ViolationReason::ConnectorNotInZone);
        assert_eq!(v.tool, "github.create_issue");
        assert_eq!(v.zone, zone_public());
        assert!(v.message.contains("not available"));
    }

    #[test]
    fn violation_with_available_in() {
        let v = ZoneViolation::new("vault.get_secret", zone_public(), ViolationReason::ConnectorNotInZone)
            .with_available_in(vec![zone_private()]);
        assert_eq!(v.available_in.len(), 1);
    }

    #[test]
    fn violation_display() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::NoToken);
        let s = v.to_string();
        assert!(s.contains("not available"));
    }

    // ── ZoneRegistry ──────────────────────────────────────────────

    #[test]
    fn registry_empty() {
        let reg = ZoneRegistry::new();
        assert_eq!(reg.tool_count(), 0);
        assert!(reg.known_zones().is_empty());
    }

    #[test]
    fn registry_register_tool() {
        let mut reg = ZoneRegistry::new();
        reg.register_tool(ZoneScopedTool::new("github", "create_issue").with_zone(zone_work()));
        assert_eq!(reg.tool_count(), 1);
        assert!(reg.has_zone(&zone_work()));
    }

    #[test]
    fn registry_tools_in_zone() {
        let reg = sample_registry();
        let work_tools = reg.tools_in_zone(&zone_work());
        assert_eq!(work_tools.len(), 3); // github.create_issue, github.list_repos, slack.send_message
        let public_tools = reg.tools_in_zone(&zone_public());
        assert_eq!(public_tools.len(), 2); // github.create_issue, github.list_repos
        let private_tools = reg.tools_in_zone(&zone_private());
        assert_eq!(private_tools.len(), 1); // vault.get_secret
    }

    #[test]
    fn registry_tools_for_connector() {
        let reg = sample_registry();
        let github_work = reg.tools_for_connector_in_zone("github", &zone_work());
        assert_eq!(github_work.len(), 2);
        let slack_public = reg.tools_for_connector_in_zone("slack", &zone_public());
        assert!(slack_public.is_empty());
    }

    #[test]
    fn registry_tool_count_in_zone() {
        let reg = sample_registry();
        assert_eq!(reg.tool_count_in_zone(&zone_work()), 3);
        assert_eq!(reg.tool_count_in_zone(&zone_private()), 1);
    }

    #[test]
    fn registry_connectors_in_zone() {
        let reg = sample_registry();
        let connectors = reg.connectors_in_zone(&zone_work());
        assert!(connectors.contains("github"));
        assert!(connectors.contains("slack"));
        assert!(!connectors.contains("vault"));
    }

    // ── validate_tool_call ────────────────────────────────────────

    #[test]
    fn validate_succeeds() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_no_token() {
        let reg = sample_registry();
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::NoToken);
    }

    #[test]
    fn validate_wrong_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_public()); // Token for public
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::UnknownZone);
    }

    #[test]
    fn validate_tool_not_in_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_public());
        let result = validate_tool_call(&reg, "slack.send_message", &zone_public(), Some(&token));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::ConnectorNotInZone);
    }

    #[test]
    fn validate_connector_restricted() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("github"); // Only github allowed
        let result = validate_tool_call(&reg, "slack.send_message", &zone_work(), Some(&token));
        assert!(result.is_err());
    }

    #[test]
    fn validate_operation_denied() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_denied_operation("create_issue");
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::OperationDenied);
    }

    #[test]
    fn validate_unknown_tool() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let result = validate_tool_call(&reg, "nonexistent.op", &zone_work(), Some(&token));
        assert!(result.is_err());
    }

    // ── filter_tools_for_zone ─────────────────────────────────────

    #[test]
    fn filter_tools_basic() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_tools_restricted_connector() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("github");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 2); // Only github tools
    }

    #[test]
    fn filter_tools_denied_operation() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_denied_operation("create_issue");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 2); // list_repos + send_message
    }

    #[test]
    fn filter_tools_different_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_public());
        let filtered = filter_tools_for_zone(&reg.tools, &zone_public(), &token);
        assert_eq!(filtered.len(), 2); // Only github tools in public
    }

    // ── format helpers ────────────────────────────────────────────

    #[test]
    fn format_zone_tools_display() {
        let reg = sample_registry();
        let tools = reg.tools_in_zone(&zone_work());
        let s = format_zone_tools(&zone_work(), &tools);
        assert!(s.contains("z:work (3 tools)"));
        assert!(s.contains("github:"));
        assert!(s.contains("slack:"));
    }

    #[test]
    fn format_violation_display() {
        let v = ZoneViolation::new("vault.get_secret", zone_public(), ViolationReason::ConnectorNotInZone)
            .with_available_in(vec![zone_private()]);
        let s = format_violation(&v);
        assert!(s.contains("not available"));
        assert!(s.contains("z:private"));
    }

    #[test]
    fn format_violation_no_alternatives() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::NoToken);
        let s = format_violation(&v);
        assert!(!s.contains("Available in"));
    }

    // ── parse_zone ────────────────────────────────────────────────

    #[test]
    fn parse_zone_with_prefix() {
        let z = parse_zone("z:work");
        assert_eq!(z.as_str(), "z:work");
    }

    #[test]
    fn parse_zone_without_prefix() {
        let z = parse_zone("work");
        assert_eq!(z.as_str(), "z:work");
    }

    #[test]
    fn parse_zone_with_whitespace() {
        let z = parse_zone("  z:work  ");
        assert_eq!(z.as_str(), "z:work");
    }
}
