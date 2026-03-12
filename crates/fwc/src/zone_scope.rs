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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub fn new(connector: impl Into<String>, operation: impl Into<String>) -> Self {
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub fn new(tool: impl Into<String>, zone: ZoneId, reason: ViolationReason) -> Self {
        let tool = tool.into();
        let message = format!("Tool '{tool}' not available in zone '{zone}': {reason}");
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
    pub const fn new() -> Self {
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
        self.tools.iter().filter(|t| t.available_in(zone)).collect()
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
    pub const fn known_zones(&self) -> &BTreeSet<ZoneId> {
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
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::NoToken,
        ));
    };

    // Token must match zone
    if token.zone != *zone {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::UnknownZone,
        ));
    }

    // Token must not be expired
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if token.is_expired(now) {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::TokenExpired,
        ));
    }

    // Find the tool
    let tool = registry.tools.iter().find(|t| t.name == tool_name);

    let Some(tool) = tool else {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::ConnectorNotInZone,
        ));
    };

    // Tool must be available in zone
    if !tool.available_in(zone) {
        let available: Vec<ZoneId> = tool.zones.iter().cloned().collect();
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::ConnectorNotInZone,
        )
        .with_available_in(available));
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
        by_connector.entry(&tool.connector).or_default().push(tool);
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
        use std::fmt::Write;
        let zones: Vec<&str> = violation.available_in.iter().map(ZoneId::as_str).collect();
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
        reg.register_tool(ZoneScopedTool::new("slack", "send_message").with_zone(zone_work()));
        reg.register_tool(ZoneScopedTool::new("vault", "get_secret").with_zone(zone_private()));
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
        let t = sample_token(zone_work()).with_denied_operation("delete_repo");
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
        let t =
            ZoneScopedTool::new("github", "create_issue").with_description("Create a GitHub issue");
        assert_eq!(t.description, "Create a GitHub issue");
    }

    #[test]
    fn tool_serializes() {
        let t = ZoneScopedTool::new("github", "create_issue").with_zone(zone_work());
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
        let v = ZoneViolation::new(
            "github.create_issue",
            zone_public(),
            ViolationReason::ConnectorNotInZone,
        );
        assert_eq!(v.tool, "github.create_issue");
        assert_eq!(v.zone, zone_public());
        assert!(v.message.contains("not available"));
    }

    #[test]
    fn violation_with_available_in() {
        let v = ZoneViolation::new(
            "vault.get_secret",
            zone_public(),
            ViolationReason::ConnectorNotInZone,
        )
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
        assert_eq!(
            result.unwrap_err().reason,
            ViolationReason::ConnectorNotInZone
        );
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
        let v = ZoneViolation::new(
            "vault.get_secret",
            zone_public(),
            ViolationReason::ConnectorNotInZone,
        )
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

    // ── ZoneId edge cases ────────────────────────────────────────

    #[test]
    fn zone_id_empty() {
        let z = ZoneId::new("");
        assert_eq!(z.as_str(), "");
        assert!(!z.is_public());
        assert!(!z.is_well_known());
    }

    #[test]
    fn zone_id_no_prefix() {
        let z = ZoneId::new("custom_zone");
        assert!(!z.is_well_known());
        assert!(!z.is_public());
        assert_eq!(z.to_string(), "custom_zone");
    }

    #[test]
    fn zone_id_colon_only() {
        let z = ZoneId::new("z:");
        assert!(z.is_well_known());
        assert!(!z.is_public());
    }

    #[test]
    fn zone_id_display() {
        let z = ZoneId::new("z:staging");
        assert_eq!(format!("{z}"), "z:staging");
    }

    #[test]
    fn zone_id_hash_set() {
        let mut set = BTreeSet::new();
        set.insert(ZoneId::new("z:a"));
        set.insert(ZoneId::new("z:a"));
        set.insert(ZoneId::new("z:b"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn zone_id_serde_roundtrip() {
        let z = ZoneId::new("z:test");
        let json = serde_json::to_string(&z).unwrap();
        let z2: ZoneId = serde_json::from_str(&json).unwrap();
        assert_eq!(z, z2);
    }

    #[test]
    fn zone_id_from_str_impl() {
        let z: ZoneId = "z:derived".into();
        assert_eq!(z, ZoneId::new("z:derived"));
    }

    #[test]
    fn zone_id_clone() {
        let z = ZoneId::new("z:work");
        let z2 = z.clone();
        assert_eq!(z, z2);
    }

    // ── CapabilityToken edge cases ───────────────────────────────

    #[test]
    fn token_expiry_exact_boundary() {
        let t = CapabilityToken::new(zone_work(), "agent").with_expiry(100);
        assert!(!t.is_expired(100)); // now == expires_at → NOT expired
        assert!(t.is_expired(101)); // now > expires_at → expired
    }

    #[test]
    fn token_expiry_zero_means_no_expiry() {
        let t = CapabilityToken::new(zone_work(), "agent").with_expiry(0);
        assert!(!t.is_expired(0));
        assert!(!t.is_expired(u64::MAX));
    }

    #[test]
    fn token_multiple_connectors() {
        let t = CapabilityToken::new(zone_work(), "agent")
            .with_connector("github")
            .with_connector("slack")
            .with_connector("jira");
        assert!(t.allows_connector("github"));
        assert!(t.allows_connector("slack"));
        assert!(t.allows_connector("jira"));
        assert!(!t.allows_connector("linear"));
    }

    #[test]
    fn token_multiple_denied_operations() {
        let t = CapabilityToken::new(zone_work(), "agent")
            .with_denied_operation("delete_repo")
            .with_denied_operation("delete_org");
        assert!(t.is_operation_denied("delete_repo"));
        assert!(t.is_operation_denied("delete_org"));
        assert!(!t.is_operation_denied("create_issue"));
    }

    #[test]
    fn token_serde_roundtrip_full() {
        let t = CapabilityToken::new(zone_work(), "agent-42")
            .with_connector("github")
            .with_denied_operation("delete")
            .with_expiry(99999);
        let json = serde_json::to_string(&t).unwrap();
        let t2: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.zone, zone_work());
        assert_eq!(t2.principal, "agent-42");
        assert!(t2.allows_connector("github"));
        assert!(!t2.allows_connector("slack"));
        assert!(t2.is_operation_denied("delete"));
        assert_eq!(t2.expires_at, 99999);
    }

    #[test]
    fn token_clone() {
        let t = CapabilityToken::new(zone_work(), "agent").with_connector("github");
        let t2 = t.clone();
        assert_eq!(t.zone, t2.zone);
        assert!(t2.allows_connector("github"));
    }

    // ── ZoneScopedTool edge cases ────────────────────────────────

    #[test]
    fn tool_name_format() {
        let t = ZoneScopedTool::new("my-connector", "some_operation");
        assert_eq!(t.name, "my-connector.some_operation");
    }

    #[test]
    fn tool_no_zones() {
        let t = ZoneScopedTool::new("github", "create_issue");
        assert!(t.zones.is_empty());
        assert!(!t.available_in(&zone_work()));
    }

    #[test]
    fn tool_duplicate_zone_no_effect() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_zone(zone_work())
            .with_zone(zone_work());
        assert_eq!(t.zones.len(), 1);
    }

    #[test]
    fn tool_serde_roundtrip() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_zone(zone_work())
            .with_description("Create issue");
        let json = serde_json::to_string(&t).unwrap();
        let t2: ZoneScopedTool = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.name, "github.create_issue");
        assert_eq!(t2.description, "Create issue");
    }

    // ── ViolationReason additional ───────────────────────────────

    #[test]
    fn violation_reason_display_unknown_zone() {
        assert_eq!(
            ViolationReason::UnknownZone.to_string(),
            "zone not recognized"
        );
    }

    #[test]
    fn violation_reason_serde_all() {
        for reason in &[
            ViolationReason::ConnectorNotInZone,
            ViolationReason::OperationDenied,
            ViolationReason::TokenExpired,
            ViolationReason::NoToken,
            ViolationReason::UnknownZone,
        ] {
            let json = serde_json::to_string(reason).unwrap();
            let r2: ViolationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, r2);
        }
    }

    // ── ZoneViolation additional ─────────────────────────────────

    #[test]
    fn violation_serde_roundtrip() {
        let v = ZoneViolation::new(
            "github.create_issue",
            zone_work(),
            ViolationReason::OperationDenied,
        )
        .with_available_in(vec![zone_public()]);
        let json = serde_json::to_string(&v).unwrap();
        let v2: ZoneViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v2.tool, "github.create_issue");
        assert_eq!(v2.reason, ViolationReason::OperationDenied);
    }

    #[test]
    fn violation_message_format() {
        let v = ZoneViolation::new(
            "vault.get_secret",
            ZoneId::new("z:public"),
            ViolationReason::TokenExpired,
        );
        assert!(v.message.contains("vault.get_secret"));
        assert!(v.message.contains("z:public"));
        assert!(v.message.contains("token expired"));
    }

    #[test]
    fn violation_display_matches_message() {
        let v = ZoneViolation::new("test.op", zone_work(), ViolationReason::NoToken);
        assert_eq!(v.to_string(), v.message);
    }

    #[test]
    fn violation_empty_available_in() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::NoToken);
        assert!(v.available_in.is_empty());
    }

    // ── ZoneRegistry additional ──────────────────────────────────

    #[test]
    fn registry_has_zone_unknown() {
        let reg = sample_registry();
        assert!(!reg.has_zone(&ZoneId::new("z:staging")));
    }

    #[test]
    fn registry_known_zones() {
        let reg = sample_registry();
        let zones = reg.known_zones();
        assert!(zones.contains(&zone_work()));
        assert!(zones.contains(&zone_public()));
        assert!(zones.contains(&zone_private()));
        assert_eq!(zones.len(), 3);
    }

    #[test]
    fn registry_connectors_in_zone_empty() {
        let reg = sample_registry();
        let connectors = reg.connectors_in_zone(&ZoneId::new("z:staging"));
        assert!(connectors.is_empty());
    }

    #[test]
    fn registry_connectors_in_zone_public() {
        let reg = sample_registry();
        let connectors = reg.connectors_in_zone(&zone_public());
        assert_eq!(connectors.len(), 1);
        assert!(connectors.contains("github"));
    }

    #[test]
    fn registry_tool_count_in_zone_unknown() {
        let reg = sample_registry();
        assert_eq!(reg.tool_count_in_zone(&ZoneId::new("z:staging")), 0);
    }

    #[test]
    fn registry_clone() {
        let reg = sample_registry();
        let reg2 = reg.clone();
        assert_eq!(reg.tool_count(), reg2.tool_count());
        assert_eq!(reg.known_zones().len(), reg2.known_zones().len());
    }

    // ── validate_tool_call additional ────────────────────────────

    #[test]
    fn validate_expired_token() {
        let reg = sample_registry();
        let token = CapabilityToken::new(zone_work(), "agent").with_expiry(1); // expired
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::TokenExpired);
    }

    #[test]
    fn validate_tool_not_in_zone_has_alternatives() {
        let reg = sample_registry();
        let token = sample_token(zone_private());
        // slack.send_message is in z:work, not z:private
        let result = validate_tool_call(&reg, "slack.send_message", &zone_private(), Some(&token));
        let err = result.unwrap_err();
        assert_eq!(err.reason, ViolationReason::ConnectorNotInZone);
        assert!(!err.available_in.is_empty());
        assert!(err.available_in.contains(&zone_work()));
    }

    #[test]
    fn validate_multiple_denied_operations() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_denied_operation("create_issue")
            .with_denied_operation("list_repos");
        assert!(
            validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token)).is_err()
        );
        assert!(validate_tool_call(&reg, "github.list_repos", &zone_work(), Some(&token)).is_err());
        // slack.send_message not denied
        assert!(validate_tool_call(&reg, "slack.send_message", &zone_work(), Some(&token)).is_ok());
    }

    #[test]
    fn validate_connector_restricted_by_token() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("slack");
        // Only slack allowed, github should fail
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().reason,
            ViolationReason::ConnectorNotInZone
        );
    }

    // ── filter_tools_for_zone additional ─────────────────────────

    #[test]
    fn filter_tools_empty_zone() {
        let reg = sample_registry();
        let token = sample_token(ZoneId::new("z:staging"));
        let filtered = filter_tools_for_zone(&reg.tools, &ZoneId::new("z:staging"), &token);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_tools_all_denied() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_denied_operation("create_issue")
            .with_denied_operation("list_repos")
            .with_denied_operation("send_message");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_tools_multiple_connectors() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_connector("github")
            .with_connector("slack");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 3);
    }

    // ── format helpers additional ────────────────────────────────

    #[test]
    fn format_zone_tools_empty() {
        let tools: Vec<&ZoneScopedTool> = vec![];
        let s = format_zone_tools(&zone_work(), &tools);
        assert!(s.contains("z:work (0 tools)"));
    }

    #[test]
    fn format_violation_multiple_zones() {
        let v = ZoneViolation::new(
            "test.op",
            zone_public(),
            ViolationReason::ConnectorNotInZone,
        )
        .with_available_in(vec![zone_work(), zone_private()]);
        let s = format_violation(&v);
        assert!(s.contains("z:work"));
        assert!(s.contains("z:private"));
    }

    // ── parse_zone additional ────────────────────────────────────

    #[test]
    fn parse_zone_empty_string() {
        let z = parse_zone("");
        assert_eq!(z.as_str(), "z:");
    }

    #[test]
    fn parse_zone_z_colon_only() {
        let z = parse_zone("z:");
        assert_eq!(z.as_str(), "z:");
    }

    #[test]
    fn parse_zone_whitespace_only() {
        let z = parse_zone("   ");
        assert_eq!(z.as_str(), "z:");
    }

    #[test]
    fn parse_zone_double_prefix() {
        let z = parse_zone("z:z:work");
        // Already starts with "z:", returned as-is
        assert_eq!(z.as_str(), "z:z:work");
    }

    #[test]
    fn parse_zone_special_chars() {
        let z = parse_zone("my-zone_1");
        assert_eq!(z.as_str(), "z:my-zone_1");
    }

    // ── ZoneId extended ──────────────────────────────────────────────

    #[test]
    fn zone_id_long_string() {
        let long = format!("z:{}", "a".repeat(1000));
        let z = ZoneId::new(&long);
        assert_eq!(z.as_str(), long);
        assert!(z.is_well_known());
    }

    #[test]
    fn zone_id_unicode() {
        let z = ZoneId::new("z:trabajo");
        assert!(z.is_well_known());
        assert_eq!(z.as_str(), "z:trabajo");
    }

    #[test]
    fn zone_id_with_special_chars() {
        let z = ZoneId::new("z:my-zone_1.2");
        assert!(z.is_well_known());
        assert_eq!(z.to_string(), "z:my-zone_1.2");
    }

    #[test]
    fn zone_id_from_string_owned() {
        let s = String::from("z:owned");
        let z = ZoneId::new(s);
        assert_eq!(z.as_str(), "z:owned");
    }

    #[test]
    fn zone_id_hash_consistency() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(ZoneId::new("z:test"), 42);
        assert_eq!(map.get(&ZoneId::new("z:test")), Some(&42));
        assert_eq!(map.get(&ZoneId::new("z:other")), None);
    }

    #[test]
    fn zone_id_ord_multiple() {
        let mut zones = vec![
            ZoneId::new("z:work"),
            ZoneId::new("z:alpha"),
            ZoneId::new("z:public"),
            ZoneId::new("z:beta"),
        ];
        zones.sort();
        assert_eq!(zones[0].as_str(), "z:alpha");
        assert_eq!(zones[1].as_str(), "z:beta");
        assert_eq!(zones[2].as_str(), "z:public");
        assert_eq!(zones[3].as_str(), "z:work");
    }

    #[test]
    fn zone_id_public_exact_match() {
        // Only exact "z:public" is public
        assert!(!ZoneId::new("z:public2").is_public());
        assert!(!ZoneId::new("z:publc").is_public());
        assert!(!ZoneId::new("z:PUBLIC").is_public());
    }

    #[test]
    fn zone_id_well_known_prefix_only() {
        assert!(!ZoneId::new("Z:work").is_well_known());
        assert!(!ZoneId::new("zz:work").is_well_known());
        assert!(ZoneId::new("z:").is_well_known());
        assert!(ZoneId::new("z:x").is_well_known());
    }

    #[test]
    fn zone_id_serde_empty() {
        let z = ZoneId::new("");
        let json = serde_json::to_string(&z).unwrap();
        let z2: ZoneId = serde_json::from_str(&json).unwrap();
        assert_eq!(z, z2);
        assert_eq!(z2.as_str(), "");
    }

    #[test]
    fn zone_id_btree_set_ordering() {
        let mut set = BTreeSet::new();
        set.insert(ZoneId::new("z:c"));
        set.insert(ZoneId::new("z:a"));
        set.insert(ZoneId::new("z:b"));
        let v: Vec<&str> = set.iter().map(ZoneId::as_str).collect();
        assert_eq!(v, vec!["z:a", "z:b", "z:c"]);
    }

    #[test]
    fn zone_id_display_format() {
        let z = ZoneId::new("z:formatted");
        assert_eq!(format!("zone={z}"), "zone=z:formatted");
    }

    // ── CapabilityToken extended ─────────────────────────────────────

    #[test]
    fn token_default_timestamps() {
        let t = CapabilityToken::new(zone_work(), "agent");
        assert_eq!(t.issued_at, 0);
        assert_eq!(t.expires_at, 0);
    }

    #[test]
    fn token_empty_principal() {
        let t = CapabilityToken::new(zone_work(), "");
        assert_eq!(t.principal, "");
    }

    #[test]
    fn token_with_connector_chaining() {
        let t = CapabilityToken::new(zone_work(), "agent")
            .with_connector("a")
            .with_connector("b")
            .with_connector("c")
            .with_connector("a"); // duplicate
        assert_eq!(t.allowed_connectors.len(), 3);
        assert!(t.allows_connector("a"));
        assert!(t.allows_connector("b"));
        assert!(t.allows_connector("c"));
    }

    #[test]
    fn token_denied_ops_chaining() {
        let t = CapabilityToken::new(zone_work(), "agent")
            .with_denied_operation("delete")
            .with_denied_operation("destroy")
            .with_denied_operation("delete"); // duplicate
        assert_eq!(t.denied_operations.len(), 2);
    }

    #[test]
    fn token_expiry_boundary_exact_equals() {
        let t = CapabilityToken::new(zone_work(), "agent").with_expiry(100);
        // now == expires_at is NOT expired (now > expires_at is the condition)
        assert!(!t.is_expired(99));
        assert!(!t.is_expired(100));
        assert!(t.is_expired(101));
    }

    #[test]
    fn token_expiry_max_u64() {
        let t = CapabilityToken::new(zone_work(), "agent").with_expiry(u64::MAX);
        assert!(!t.is_expired(0));
        assert!(!t.is_expired(u64::MAX - 1));
        assert!(!t.is_expired(u64::MAX));
    }

    #[test]
    fn token_allows_all_when_empty_set() {
        let t = CapabilityToken::new(zone_work(), "agent");
        // Empty allowed_connectors means ALL connectors are allowed
        assert!(t.allows_connector("anything"));
        assert!(t.allows_connector(""));
        assert!(t.allows_connector("some-random-connector"));
    }

    #[test]
    fn token_denies_when_not_in_allowed_set() {
        let t = CapabilityToken::new(zone_work(), "agent").with_connector("only_this");
        assert!(t.allows_connector("only_this"));
        assert!(!t.allows_connector("not_this"));
        assert!(!t.allows_connector(""));
    }

    #[test]
    fn token_denied_op_empty_string() {
        let t = CapabilityToken::new(zone_work(), "agent").with_denied_operation("");
        assert!(t.is_operation_denied(""));
        assert!(!t.is_operation_denied("something"));
    }

    #[test]
    fn token_serde_empty_sets() {
        let t = CapabilityToken::new(zone_work(), "agent");
        let json = serde_json::to_string(&t).unwrap();
        let t2: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert!(t2.allowed_connectors.is_empty());
        assert!(t2.denied_operations.is_empty());
        assert_eq!(t2.expires_at, 0);
        assert_eq!(t2.issued_at, 0);
    }

    #[test]
    fn token_serde_with_all_fields() {
        let t = CapabilityToken::new(zone_private(), "admin-agent")
            .with_connector("vault")
            .with_connector("1password")
            .with_denied_operation("delete_all")
            .with_denied_operation("purge")
            .with_expiry(9999999);
        let json = serde_json::to_string(&t).unwrap();
        let t2: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.zone, zone_private());
        assert_eq!(t2.principal, "admin-agent");
        assert_eq!(t2.allowed_connectors.len(), 2);
        assert_eq!(t2.denied_operations.len(), 2);
        assert_eq!(t2.expires_at, 9999999);
    }

    #[test]
    fn token_clone_independence() {
        let t = CapabilityToken::new(zone_work(), "agent").with_connector("github");
        let mut t2 = t.clone();
        t2.allowed_connectors.insert("slack".into());
        // Original should not be affected
        assert!(!t.allows_connector("slack") || t.allowed_connectors.is_empty());
        assert_eq!(t.allowed_connectors.len(), 1);
        assert_eq!(t2.allowed_connectors.len(), 2);
    }

    // ── ZoneScopedTool extended ──────────────────────────────────────

    #[test]
    fn tool_empty_connector_and_operation() {
        let t = ZoneScopedTool::new("", "");
        assert_eq!(t.name, ".");
        assert_eq!(t.connector, "");
        assert_eq!(t.operation, "");
    }

    #[test]
    fn tool_default_description_empty() {
        let t = ZoneScopedTool::new("github", "list_repos");
        assert_eq!(t.description, "");
    }

    #[test]
    fn tool_multiple_zones() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_zone(zone_work())
            .with_zone(zone_public())
            .with_zone(zone_private());
        assert_eq!(t.zones.len(), 3);
        assert!(t.available_in(&zone_work()));
        assert!(t.available_in(&zone_public()));
        assert!(t.available_in(&zone_private()));
    }

    #[test]
    fn tool_available_in_empty_zones() {
        let t = ZoneScopedTool::new("github", "list");
        assert!(!t.available_in(&zone_work()));
        assert!(!t.available_in(&zone_public()));
    }

    #[test]
    fn tool_serde_roundtrip_full() {
        let t = ZoneScopedTool::new("slack", "send_message")
            .with_zone(zone_work())
            .with_zone(zone_private())
            .with_description("Send a Slack message");
        let json = serde_json::to_string(&t).unwrap();
        let t2: ZoneScopedTool = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.name, "slack.send_message");
        assert_eq!(t2.connector, "slack");
        assert_eq!(t2.operation, "send_message");
        assert_eq!(t2.description, "Send a Slack message");
        assert_eq!(t2.zones.len(), 2);
        assert!(t2.available_in(&zone_work()));
        assert!(t2.available_in(&zone_private()));
    }

    #[test]
    fn tool_clone_independence() {
        let t = ZoneScopedTool::new("github", "list").with_zone(zone_work());
        let mut t2 = t.clone();
        t2.zones.insert(zone_public());
        assert_eq!(t.zones.len(), 1);
        assert_eq!(t2.zones.len(), 2);
    }

    #[test]
    fn tool_debug_output() {
        let t = ZoneScopedTool::new("test", "op");
        let debug = format!("{t:?}");
        assert!(debug.contains("ZoneScopedTool"));
        assert!(debug.contains("test.op"));
    }

    // ── ViolationReason extended ─────────────────────────────────────

    #[test]
    fn violation_reason_equality() {
        assert_eq!(ViolationReason::NoToken, ViolationReason::NoToken);
        assert_ne!(ViolationReason::NoToken, ViolationReason::TokenExpired);
    }

    #[test]
    fn violation_reason_clone() {
        let r = ViolationReason::OperationDenied;
        let r2 = r.clone();
        assert_eq!(r, r2);
    }

    #[test]
    fn violation_reason_debug() {
        let r = ViolationReason::ConnectorNotInZone;
        let debug = format!("{r:?}");
        assert!(debug.contains("ConnectorNotInZone"));
    }

    #[test]
    fn violation_reason_all_variants_display() {
        let variants = [
            (ViolationReason::ConnectorNotInZone, "connector not authorized in zone"),
            (ViolationReason::OperationDenied, "operation explicitly denied"),
            (ViolationReason::TokenExpired, "capability token expired"),
            (ViolationReason::NoToken, "no capability token provided"),
            (ViolationReason::UnknownZone, "zone not recognized"),
        ];
        for (variant, expected) in &variants {
            assert_eq!(variant.to_string(), *expected);
        }
    }

    #[test]
    fn violation_reason_serde_roundtrip_all() {
        let variants = [
            ViolationReason::ConnectorNotInZone,
            ViolationReason::OperationDenied,
            ViolationReason::TokenExpired,
            ViolationReason::NoToken,
            ViolationReason::UnknownZone,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let v2: ViolationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, v2);
        }
    }

    #[test]
    fn violation_reason_snake_case_serialization() {
        assert_eq!(
            serde_json::to_value(ViolationReason::ConnectorNotInZone).unwrap(),
            "connector_not_in_zone"
        );
        assert_eq!(
            serde_json::to_value(ViolationReason::OperationDenied).unwrap(),
            "operation_denied"
        );
        assert_eq!(
            serde_json::to_value(ViolationReason::TokenExpired).unwrap(),
            "token_expired"
        );
        assert_eq!(
            serde_json::to_value(ViolationReason::UnknownZone).unwrap(),
            "unknown_zone"
        );
    }

    // ── ZoneViolation extended ───────────────────────────────────────

    #[test]
    fn violation_all_reasons_produce_valid_message() {
        let reasons = [
            ViolationReason::ConnectorNotInZone,
            ViolationReason::OperationDenied,
            ViolationReason::TokenExpired,
            ViolationReason::NoToken,
            ViolationReason::UnknownZone,
        ];
        for reason in &reasons {
            let v = ZoneViolation::new("test.op", zone_work(), reason.clone());
            assert!(v.message.contains("test.op"));
            assert!(v.message.contains("z:work"));
            assert!(!v.message.is_empty());
        }
    }

    #[test]
    fn violation_serde_roundtrip_full() {
        let v = ZoneViolation::new("vault.secret", zone_private(), ViolationReason::TokenExpired)
            .with_available_in(vec![zone_work(), zone_public()]);
        let json = serde_json::to_string(&v).unwrap();
        let v2: ZoneViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v2.tool, "vault.secret");
        assert_eq!(v2.zone, zone_private());
        assert_eq!(v2.reason, ViolationReason::TokenExpired);
        assert_eq!(v2.available_in.len(), 2);
        assert!(v2.available_in.contains(&zone_work()));
        assert!(v2.available_in.contains(&zone_public()));
    }

    #[test]
    fn violation_clone() {
        let v = ZoneViolation::new("test.op", zone_work(), ViolationReason::NoToken)
            .with_available_in(vec![zone_public()]);
        let v2 = v.clone();
        assert_eq!(v.tool, v2.tool);
        assert_eq!(v.zone, v2.zone);
        assert_eq!(v.reason, v2.reason);
        assert_eq!(v.message, v2.message);
        assert_eq!(v.available_in.len(), v2.available_in.len());
    }

    #[test]
    fn violation_debug() {
        let v = ZoneViolation::new("test.op", zone_work(), ViolationReason::NoToken);
        let debug = format!("{v:?}");
        assert!(debug.contains("ZoneViolation"));
    }

    #[test]
    fn violation_with_empty_available_in() {
        let v = ZoneViolation::new("test.op", zone_work(), ViolationReason::NoToken)
            .with_available_in(vec![]);
        assert!(v.available_in.is_empty());
    }

    // ── ZoneRegistry extended ────────────────────────────────────────

    #[test]
    fn registry_multiple_tools_same_connector() {
        let mut reg = ZoneRegistry::new();
        reg.register_tool(ZoneScopedTool::new("github", "create_issue").with_zone(zone_work()));
        reg.register_tool(ZoneScopedTool::new("github", "list_repos").with_zone(zone_work()));
        reg.register_tool(ZoneScopedTool::new("github", "delete_repo").with_zone(zone_work()));
        assert_eq!(reg.tool_count(), 3);
        assert_eq!(reg.tools_for_connector_in_zone("github", &zone_work()).len(), 3);
    }

    #[test]
    fn registry_tool_in_multiple_zones() {
        let mut reg = ZoneRegistry::new();
        reg.register_tool(
            ZoneScopedTool::new("github", "create_issue")
                .with_zone(zone_work())
                .with_zone(zone_public())
                .with_zone(zone_private()),
        );
        assert_eq!(reg.known_zones().len(), 3);
        assert_eq!(reg.tools_in_zone(&zone_work()).len(), 1);
        assert_eq!(reg.tools_in_zone(&zone_public()).len(), 1);
        assert_eq!(reg.tools_in_zone(&zone_private()).len(), 1);
    }

    #[test]
    fn registry_no_tools_in_zone() {
        let reg = sample_registry();
        let z = ZoneId::new("z:staging");
        assert!(reg.tools_in_zone(&z).is_empty());
        assert_eq!(reg.tool_count_in_zone(&z), 0);
        assert!(reg.connectors_in_zone(&z).is_empty());
    }

    #[test]
    fn registry_tools_for_nonexistent_connector() {
        let reg = sample_registry();
        let tools = reg.tools_for_connector_in_zone("nonexistent", &zone_work());
        assert!(tools.is_empty());
    }

    #[test]
    fn registry_default_is_empty() {
        let reg = ZoneRegistry::default();
        assert_eq!(reg.tool_count(), 0);
        assert!(reg.known_zones().is_empty());
    }

    #[test]
    fn registry_debug() {
        let reg = ZoneRegistry::new();
        let debug = format!("{reg:?}");
        assert!(debug.contains("ZoneRegistry"));
    }

    #[test]
    fn registry_clone_independence() {
        let mut reg = sample_registry();
        let reg2 = reg.clone();
        reg.register_tool(ZoneScopedTool::new("new", "tool").with_zone(zone_work()));
        assert_eq!(reg.tool_count(), 5);
        assert_eq!(reg2.tool_count(), 4);
    }

    #[test]
    fn registry_connectors_in_zone_deduplicates() {
        let reg = sample_registry();
        // github has 2 tools in z:work, but should appear once in connector set
        let connectors = reg.connectors_in_zone(&zone_work());
        let count = connectors.iter().filter(|c| *c == "github").count();
        assert_eq!(count, 1);
    }

    // ── validate_tool_call extended ──────────────────────────────────

    #[test]
    fn validate_all_tools_in_zone_with_valid_token() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        assert!(validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token)).is_ok());
        assert!(validate_tool_call(&reg, "github.list_repos", &zone_work(), Some(&token)).is_ok());
        assert!(validate_tool_call(&reg, "slack.send_message", &zone_work(), Some(&token)).is_ok());
    }

    #[test]
    fn validate_private_tool_requires_private_token() {
        let reg = sample_registry();
        let token = sample_token(zone_private());
        assert!(validate_tool_call(&reg, "vault.get_secret", &zone_private(), Some(&token)).is_ok());
    }

    #[test]
    fn validate_private_tool_fails_with_work_token() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let result = validate_tool_call(&reg, "vault.get_secret", &zone_work(), Some(&token));
        assert!(result.is_err());
        // vault.get_secret is only in z:private, not z:work
        assert_eq!(result.unwrap_err().reason, ViolationReason::ConnectorNotInZone);
    }

    #[test]
    fn validate_nonexistent_tool_fails() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let err = validate_tool_call(&reg, "does.not.exist", &zone_work(), Some(&token)).unwrap_err();
        assert_eq!(err.reason, ViolationReason::ConnectorNotInZone);
        assert_eq!(err.tool, "does.not.exist");
    }

    #[test]
    fn validate_empty_registry() {
        let reg = ZoneRegistry::new();
        let token = sample_token(zone_work());
        let result = validate_tool_call(&reg, "any.tool", &zone_work(), Some(&token));
        assert!(result.is_err());
    }

    #[test]
    fn validate_connector_restricted_allows_correct() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_connector("github")
            .with_connector("slack");
        assert!(validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token)).is_ok());
        assert!(validate_tool_call(&reg, "slack.send_message", &zone_work(), Some(&token)).is_ok());
    }

    #[test]
    fn validate_combined_connector_restriction_and_denial() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_connector("github")
            .with_denied_operation("create_issue");
        // github allowed, but create_issue denied
        assert!(validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token)).is_err());
        // list_repos should still work
        assert!(validate_tool_call(&reg, "github.list_repos", &zone_work(), Some(&token)).is_ok());
    }

    #[test]
    fn validate_violation_zone_preserved() {
        let reg = sample_registry();
        let err = validate_tool_call(&reg, "github.create_issue", &zone_work(), None).unwrap_err();
        assert_eq!(err.zone, zone_work());
    }

    #[test]
    fn validate_violation_tool_name_preserved() {
        let reg = sample_registry();
        let err = validate_tool_call(&reg, "my.custom.tool", &zone_work(), None).unwrap_err();
        assert_eq!(err.tool, "my.custom.tool");
    }

    // ── filter_tools_for_zone extended ───────────────────────────────

    #[test]
    fn filter_tools_empty_tools_list() {
        let tools: Vec<ZoneScopedTool> = vec![];
        let token = sample_token(zone_work());
        let filtered = filter_tools_for_zone(&tools, &zone_work(), &token);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_tools_all_connectors_allowed() {
        let reg = sample_registry();
        let token = sample_token(zone_work()); // empty allowed = all
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_tools_single_connector() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("slack");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].connector, "slack");
    }

    #[test]
    fn filter_tools_private_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_private());
        let filtered = filter_tools_for_zone(&reg.tools, &zone_private(), &token);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].connector, "vault");
    }

    #[test]
    fn filter_tools_denied_all_ops_in_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_private()).with_denied_operation("get_secret");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_private(), &token);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_tools_with_connector_not_in_zone() {
        let reg = sample_registry();
        // vault is only in z:private, filtering for z:work with vault connector
        let token = sample_token(zone_work()).with_connector("vault");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert!(filtered.is_empty());
    }

    // ── format_zone_tools extended ───────────────────────────────────

    #[test]
    fn format_zone_tools_single_connector() {
        let reg = sample_registry();
        let tools = reg.tools_in_zone(&zone_private());
        let s = format_zone_tools(&zone_private(), &tools);
        assert!(s.contains("z:private (1 tools)"));
        assert!(s.contains("vault:"));
        assert!(s.contains("get_secret"));
    }

    #[test]
    fn format_zone_tools_operations_listed() {
        let reg = sample_registry();
        let tools = reg.tools_in_zone(&zone_work());
        let s = format_zone_tools(&zone_work(), &tools);
        assert!(s.contains("create_issue"));
        assert!(s.contains("list_repos"));
        assert!(s.contains("send_message"));
    }

    #[test]
    fn format_zone_tools_connectors_grouped() {
        let reg = sample_registry();
        let tools = reg.tools_in_zone(&zone_work());
        let s = format_zone_tools(&zone_work(), &tools);
        // github tools should be grouped together
        let github_pos = s.find("github:").unwrap();
        let slack_pos = s.find("slack:").unwrap();
        // BTreeMap sorts by key, github < slack
        assert!(github_pos < slack_pos);
    }

    // ── format_violation extended ────────────────────────────────────

    #[test]
    fn format_violation_contains_cross_mark() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::NoToken);
        let s = format_violation(&v);
        assert!(s.starts_with('\u{2717}')); // ✗
    }

    #[test]
    fn format_violation_multiple_available_zones() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::ConnectorNotInZone)
            .with_available_in(vec![zone_public(), zone_private()]);
        let s = format_violation(&v);
        assert!(s.contains("Available in:"));
        assert!(s.contains("z:public"));
        assert!(s.contains("z:private"));
    }

    #[test]
    fn format_violation_single_available_zone() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::ConnectorNotInZone)
            .with_available_in(vec![zone_private()]);
        let s = format_violation(&v);
        assert!(s.contains("Available in: z:private"));
    }

    // ── parse_zone extended ──────────────────────────────────────────

    #[test]
    fn parse_zone_various_prefixed() {
        for name in ["z:work", "z:private", "z:public", "z:staging", "z:custom"] {
            let z = parse_zone(name);
            assert_eq!(z.as_str(), name);
        }
    }

    #[test]
    fn parse_zone_various_unprefixed() {
        for name in ["work", "private", "public", "staging", "custom"] {
            let z = parse_zone(name);
            assert_eq!(z.as_str(), &format!("z:{name}"));
        }
    }

    #[test]
    fn parse_zone_tabs_and_newlines() {
        let z = parse_zone("\t work \n");
        // trim() removes tabs and newlines
        assert_eq!(z.as_str(), "z:work");
    }

    #[test]
    fn parse_zone_already_prefixed_preserves() {
        let z = parse_zone("z:work");
        assert_eq!(z.as_str(), "z:work");
        assert!(z.is_well_known());
    }

    #[test]
    fn parse_zone_returns_well_known() {
        let z = parse_zone("test");
        assert!(z.is_well_known());
    }

    // ── Cross-cutting: token + registry interaction ──────────────────

    #[test]
    fn token_zone_mismatch_always_fails_validation() {
        let reg = sample_registry();
        let token = sample_token(zone_public());
        // Token for public, validating against work
        let err = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token)).unwrap_err();
        assert_eq!(err.reason, ViolationReason::UnknownZone);
    }

    #[test]
    fn filter_and_validate_consistency() {
        // If filter returns a tool, validate should pass for that tool
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        for tool in &filtered {
            let result = validate_tool_call(&reg, &tool.name, &zone_work(), Some(&token));
            assert!(result.is_ok(), "validate failed for filtered tool {}", tool.name);
        }
    }

    #[test]
    fn restricted_token_filter_validate_consistent() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("github");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        for tool in &filtered {
            assert_eq!(tool.connector, "github");
            let result = validate_tool_call(&reg, &tool.name, &zone_work(), Some(&token));
            assert!(result.is_ok());
        }
    }

    #[test]
    fn denied_ops_filter_validate_consistent() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_denied_operation("create_issue");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        // create_issue should not be in filtered results
        assert!(!filtered.iter().any(|t| t.operation == "create_issue"));
        for tool in &filtered {
            let result = validate_tool_call(&reg, &tool.name, &zone_work(), Some(&token));
            assert!(result.is_ok());
        }
    }

    // ── Zone ID ordering invariants ──────────────────────────────────

    #[test]
    fn zone_id_total_ordering() {
        let a = ZoneId::new("z:a");
        let b = ZoneId::new("z:b");
        let c = ZoneId::new("z:c");
        assert!(a < b);
        assert!(b < c);
        assert!(a < c); // transitivity
    }

    #[test]
    fn zone_id_partial_eq_reflexive() {
        let z = ZoneId::new("z:test");
        assert_eq!(z, z.clone());
    }

    // ── Large-scale registry tests ───────────────────────────────────

    #[test]
    fn registry_many_tools() {
        let mut reg = ZoneRegistry::new();
        for i in 0..100 {
            reg.register_tool(
                ZoneScopedTool::new(format!("conn_{i}"), format!("op_{i}"))
                    .with_zone(zone_work()),
            );
        }
        assert_eq!(reg.tool_count(), 100);
        assert_eq!(reg.tool_count_in_zone(&zone_work()), 100);
        assert_eq!(reg.connectors_in_zone(&zone_work()).len(), 100);
    }

    #[test]
    fn registry_many_zones() {
        let mut reg = ZoneRegistry::new();
        for i in 0..50 {
            reg.register_tool(
                ZoneScopedTool::new("github", format!("op_{i}"))
                    .with_zone(ZoneId::new(format!("z:zone_{i}"))),
            );
        }
        assert_eq!(reg.tool_count(), 50);
        assert_eq!(reg.known_zones().len(), 50);
    }

    #[test]
    fn filter_many_tools_performance() {
        let mut tools = Vec::new();
        for i in 0..200 {
            tools.push(
                ZoneScopedTool::new(format!("conn_{}", i % 10), format!("op_{i}"))
                    .with_zone(zone_work()),
            );
        }
        let token = sample_token(zone_work()).with_connector("conn_0");
        let filtered = filter_tools_for_zone(&tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 20); // 200/10 connectors = 20 for conn_0
    }
}
