//! SharePoint Sites, Documents, and Search module.
//!
//! Provides types and policy enforcement for SharePoint operations via
//! Microsoft Graph, including site enumeration, drive/document management,
//! search, and sharing link management. All write and share operations are
//! capability-gated with default-deny semantics and emit audit receipts.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Site
// ---------------------------------------------------------------------------

/// A SharePoint site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "webUrl")]
    pub web_url: String,
    pub description: Option<String>,
    #[serde(rename = "createdDateTime")]
    pub created_at: Option<String>,
    #[serde(rename = "lastModifiedDateTime")]
    pub last_modified_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Drive types
// ---------------------------------------------------------------------------

/// The kind of drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DriveType {
    Personal,
    Business,
    #[serde(rename = "documentLibrary")]
    DocumentLibrary,
    #[serde(other)]
    Unknown,
}

impl fmt::Display for DriveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Personal => write!(f, "personal"),
            Self::Business => write!(f, "business"),
            Self::DocumentLibrary => write!(f, "documentLibrary"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Quota information for a drive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveQuota {
    #[serde(rename = "used")]
    pub used_bytes: u64,
    #[serde(rename = "total")]
    pub total_bytes: u64,
    #[serde(rename = "remaining")]
    pub remaining_bytes: u64,
    pub state: QuotaState,
}

impl DriveQuota {
    /// Returns usage as a fraction in `[0.0, 1.0]`. Returns 0 if total is zero.
    #[must_use]
    pub fn usage_fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        self.used_bytes as f64 / self.total_bytes as f64
    }
}

/// State of a drive quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuotaState {
    Normal,
    Nearing,
    Critical,
    Exceeded,
}

impl fmt::Display for QuotaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Nearing => write!(f, "nearing"),
            Self::Critical => write!(f, "critical"),
            Self::Exceeded => write!(f, "exceeded"),
        }
    }
}

/// A SharePoint or OneDrive drive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    pub id: String,
    pub name: String,
    #[serde(rename = "driveType")]
    pub drive_type: DriveType,
    pub owner: Option<String>,
    pub quota: Option<DriveQuota>,
}

// ---------------------------------------------------------------------------
// DriveItem (SharePoint-flavored)
// ---------------------------------------------------------------------------

/// An item (file or folder) within a SharePoint drive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "size")]
    pub size_bytes: Option<u64>,
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
    #[serde(rename = "webUrl")]
    pub web_url: Option<String>,
    #[serde(rename = "createdDateTime")]
    pub created_at: Option<String>,
    #[serde(rename = "lastModifiedDateTime")]
    pub modified_at: Option<String>,
    #[serde(rename = "lastModifiedBy")]
    pub modified_by: Option<String>,
    #[serde(rename = "isFolder")]
    pub is_folder: bool,
    #[serde(rename = "parentPath")]
    pub parent_path: Option<String>,
}

impl DriveItem {
    /// Returns `true` if this item is a document (not a folder).
    #[must_use]
    pub const fn is_document(&self) -> bool {
        !self.is_folder
    }

    /// Returns the file extension, if any.
    #[must_use]
    pub fn file_extension(&self) -> Option<&str> {
        if self.is_folder {
            return None;
        }
        self.name
            .rsplit('.')
            .next()
            // Only return extension if there was an actual dot.
            .filter(|ext| ext.len() != self.name.len())
    }
}

// ---------------------------------------------------------------------------
// SharePointList
// ---------------------------------------------------------------------------

/// A SharePoint list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePointList {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "itemCount")]
    pub item_count: Option<u32>,
    #[serde(rename = "listType")]
    pub list_type: String,
}

// ---------------------------------------------------------------------------
// Search types
// ---------------------------------------------------------------------------

/// The type of entity to search for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SearchEntityType {
    DriveItem,
    ListItem,
    Site,
    Message,
}

impl fmt::Display for SearchEntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DriveItem => write!(f, "driveItem"),
            Self::ListItem => write!(f, "listItem"),
            Self::Site => write!(f, "site"),
            Self::Message => write!(f, "message"),
        }
    }
}

/// A search query for SharePoint content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub query: String,
    pub entity_types: Vec<SearchEntityType>,
    pub from_site: Option<String>,
    pub limit: u32,
    pub offset: u32,
}

/// Errors that can occur when validating a search query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchValidationError {
    EmptyQuery,
    LimitTooHigh(u32),
    NoEntityTypes,
}

impl fmt::Display for SearchValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyQuery => write!(f, "search query must not be empty"),
            Self::LimitTooHigh(n) => write!(f, "limit {n} exceeds maximum of 100"),
            Self::NoEntityTypes => write!(f, "at least one entity type is required"),
        }
    }
}

impl SearchQuery {
    /// Maximum number of results per query.
    pub const MAX_LIMIT: u32 = 100;
    /// Default number of results per query.
    pub const DEFAULT_LIMIT: u32 = 25;

    /// Create a new search query with the given text.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            entity_types: Vec::new(),
            from_site: None,
            limit: Self::DEFAULT_LIMIT,
            offset: 0,
        }
    }

    /// Add an entity type to search for.
    #[must_use]
    pub fn with_entity_type(mut self, entity_type: SearchEntityType) -> Self {
        if !self.entity_types.contains(&entity_type) {
            self.entity_types.push(entity_type);
        }
        self
    }

    /// Restrict the search to a specific site.
    #[must_use]
    pub fn from_site(mut self, site_id: impl Into<String>) -> Self {
        self.from_site = Some(site_id.into());
        self
    }

    /// Set the maximum number of results.
    #[must_use]
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Set the pagination offset.
    #[must_use]
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }

    /// Validate the query, returning errors if any.
    pub fn validate(&self) -> Result<(), SearchValidationError> {
        if self.query.trim().is_empty() {
            return Err(SearchValidationError::EmptyQuery);
        }
        if self.entity_types.is_empty() {
            return Err(SearchValidationError::NoEntityTypes);
        }
        if self.limit > Self::MAX_LIMIT {
            return Err(SearchValidationError::LimitTooHigh(self.limit));
        }
        Ok(())
    }
}

/// A single search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: String,
    pub name: String,
    pub summary: Option<String>,
    #[serde(rename = "webUrl")]
    pub web_url: Option<String>,
    pub entity_type: SearchEntityType,
    pub hit_highlights: Vec<String>,
}

/// A collection of search results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    pub results: Vec<SearchResult>,
    pub total_estimated: u64,
    pub has_more: bool,
}

impl SearchResults {
    /// Create empty search results.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            results: Vec::new(),
            total_estimated: 0,
            has_more: false,
        }
    }

    /// Number of results in this page.
    #[must_use]
    pub fn count(&self) -> usize {
        self.results.len()
    }
}

// ---------------------------------------------------------------------------
// Sharing types
// ---------------------------------------------------------------------------

/// The type of sharing link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SharingLinkType {
    View,
    Edit,
    Embed,
}

impl fmt::Display for SharingLinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::View => write!(f, "view"),
            Self::Edit => write!(f, "edit"),
            Self::Embed => write!(f, "embed"),
        }
    }
}

/// The scope of a sharing link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SharingScope {
    Anonymous,
    Organization,
    SpecificPeople,
}

impl fmt::Display for SharingScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => write!(f, "anonymous"),
            Self::Organization => write!(f, "organization"),
            Self::SpecificPeople => write!(f, "specificPeople"),
        }
    }
}

/// A sharing link for a drive item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingLink {
    pub link_id: Option<String>,
    pub link_type: SharingLinkType,
    pub scope: SharingScope,
    #[serde(rename = "webUrl")]
    pub web_url: Option<String>,
    pub expiration: Option<String>,
}

impl SharingLink {
    /// Returns `true` if this link grants write access.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        matches!(self.link_type, SharingLinkType::Edit)
    }

    /// Returns `true` if this link is publicly accessible.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        matches!(self.scope, SharingScope::Anonymous)
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// The action being attempted against the SharePoint policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharePointAction {
    Read,
    Write,
    Search,
    Share,
}

impl fmt::Display for SharePointAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Search => write!(f, "search"),
            Self::Share => write!(f, "share"),
        }
    }
}

/// Result of a policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Action is allowed without further review.
    Allow,
    /// Action is allowed but requires approval.
    RequiresApproval,
    /// Action is denied with reason.
    Deny(String),
}

impl PolicyDecision {
    /// Returns `true` if the action is allowed (with or without approval).
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::RequiresApproval)
    }

    /// Returns `true` if the action requires approval.
    #[must_use]
    pub const fn requires_approval(&self) -> bool {
        matches!(self, Self::RequiresApproval)
    }

    /// Returns `true` if the action is denied.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny(_))
    }
}

/// Policy for SharePoint operations.  Default is deny-all.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct SharePointPolicy {
    pub allow_read: bool,
    pub allow_write: bool,
    pub allow_search: bool,
    pub allow_share: bool,
    pub require_approval_for_write: bool,
    pub require_approval_for_share: bool,
    pub blocked_sites: HashSet<String>,
    pub max_upload_bytes: u64,
}

impl Default for SharePointPolicy {
    /// Default policy: deny all.
    fn default() -> Self {
        Self {
            allow_read: false,
            allow_write: false,
            allow_search: false,
            allow_share: false,
            require_approval_for_write: true,
            require_approval_for_share: true,
            blocked_sites: HashSet::new(),
            max_upload_bytes: 250 * 1024 * 1024, // 250 MiB
        }
    }
}

impl SharePointPolicy {
    /// Default deny-all policy (same as `Default::default()`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A permissive policy allowing all actions.
    #[must_use]
    pub fn new_permissive() -> Self {
        Self {
            allow_read: true,
            allow_write: true,
            allow_search: true,
            allow_share: true,
            require_approval_for_write: false,
            require_approval_for_share: false,
            blocked_sites: HashSet::new(),
            max_upload_bytes: 250 * 1024 * 1024,
        }
    }

    /// A read-only policy.
    #[must_use]
    pub fn new_readonly() -> Self {
        Self {
            allow_read: true,
            allow_write: false,
            allow_search: true,
            allow_share: false,
            require_approval_for_write: true,
            require_approval_for_share: true,
            blocked_sites: HashSet::new(),
            max_upload_bytes: 0,
        }
    }

    /// Check whether the given action is allowed, optionally against a site.
    #[must_use]
    pub fn check_action(&self, action: SharePointAction, site_id: Option<&str>) -> PolicyDecision {
        // Check blocked sites first.
        if let Some(sid) = site_id {
            if self.blocked_sites.contains(sid) {
                return PolicyDecision::Deny(format!("site '{sid}' is blocked by policy"));
            }
        }

        match action {
            SharePointAction::Read => {
                if self.allow_read {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny("read access is not allowed".into())
                }
            }
            SharePointAction::Write => {
                if !self.allow_write {
                    PolicyDecision::Deny("write access is not allowed".into())
                } else if self.require_approval_for_write {
                    PolicyDecision::RequiresApproval
                } else {
                    PolicyDecision::Allow
                }
            }
            SharePointAction::Search => {
                if self.allow_search {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny("search is not allowed".into())
                }
            }
            SharePointAction::Share => {
                if !self.allow_share {
                    PolicyDecision::Deny("sharing is not allowed".into())
                } else if self.require_approval_for_share {
                    PolicyDecision::RequiresApproval
                } else {
                    PolicyDecision::Allow
                }
            }
        }
    }

    /// Check if a file size is within the upload limit.
    #[must_use]
    pub const fn check_upload_size(&self, size_bytes: u64) -> bool {
        size_bytes <= self.max_upload_bytes
    }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// An audit event for SharePoint operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePointAuditEvent {
    pub timestamp: String,
    pub action: String,
    pub site_id: Option<String>,
    pub item_path: Option<String>,
    pub details: String,
}

impl SharePointAuditEvent {
    /// Create a new audit event with the current timestamp placeholder.
    #[must_use]
    pub fn new(action: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            timestamp: "2026-01-01T00:00:00Z".into(),
            action: action.into(),
            site_id: None,
            item_path: None,
            details: details.into(),
        }
    }

    /// Attach a site ID to the audit event.
    #[must_use]
    pub fn with_site(mut self, site_id: impl Into<String>) -> Self {
        self.site_id = Some(site_id.into());
        self
    }

    /// Attach an item path to the audit event.
    #[must_use]
    pub fn with_item(mut self, path: impl Into<String>) -> Self {
        self.item_path = Some(path.into());
        self
    }

    /// Returns a human-readable summary of this audit event.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = vec![format!("[{}] {}", self.timestamp, self.action)];
        if let Some(ref sid) = self.site_id {
            parts.push(format!("site={sid}"));
        }
        if let Some(ref path) = self.item_path {
            parts.push(format!("item={path}"));
        }
        parts.push(self.details.clone());
        parts.join(" | ")
    }
}

// ---------------------------------------------------------------------------
// Graph API URL helpers
// ---------------------------------------------------------------------------

/// Build the Graph API URL for listing sites.
#[must_use]
pub fn sites_url() -> String {
    "https://graph.microsoft.com/v1.0/sites".to_owned()
}

/// Build the Graph API URL for a specific site.
#[must_use]
pub fn site_url(site_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/sites/{site_id}")
}

/// Build the Graph API URL for the drives within a site.
#[must_use]
pub fn site_drives_url(site_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/sites/{site_id}/drives")
}

/// Build the Graph API URL for listing items in a drive root.
#[must_use]
pub fn drive_root_children_url(site_id: &str, drive_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/sites/{site_id}/drives/{drive_id}/root/children")
}

/// Build the Graph API URL for a specific item in a drive.
#[must_use]
pub fn drive_item_url(site_id: &str, drive_id: &str, item_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/sites/{site_id}/drives/{drive_id}/items/{item_id}")
}

/// Build the Graph API URL for listing lists on a site.
#[must_use]
pub fn site_lists_url(site_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/sites/{site_id}/lists")
}

/// Build the Graph API URL for search.
#[must_use]
pub fn search_url() -> String {
    "https://graph.microsoft.com/v1.0/search/query".to_owned()
}

/// Build the Graph API URL for creating sharing links.
#[must_use]
pub fn create_link_url(site_id: &str, drive_id: &str, item_id: &str) -> String {
    format!(
        "https://graph.microsoft.com/v1.0/sites/{site_id}/drives/{drive_id}/items/{item_id}/createLink"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // Site
    // ====================================================================

    #[test]
    fn site_serde_roundtrip() {
        let site = Site {
            id: "site-1".into(),
            name: "Engineering".into(),
            display_name: Some("Engineering Hub".into()),
            web_url: "https://contoso.sharepoint.com/sites/engineering".into(),
            description: Some("Central hub".into()),
            created_at: Some("2026-01-01T00:00:00Z".into()),
            last_modified_at: Some("2026-03-01T00:00:00Z".into()),
        };
        let json = serde_json::to_value(&site).unwrap();
        assert_eq!(json["id"], "site-1");
        assert_eq!(json["name"], "Engineering");
        assert_eq!(json["displayName"], "Engineering Hub");
        assert_eq!(
            json["webUrl"],
            "https://contoso.sharepoint.com/sites/engineering"
        );
        let back: Site = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "site-1");
        assert_eq!(back.display_name.as_deref(), Some("Engineering Hub"));
    }

    #[test]
    fn site_optional_fields_null() {
        let json = serde_json::json!({
            "id": "s2",
            "name": "HR",
            "webUrl": "https://contoso.sharepoint.com/sites/hr"
        });
        let site: Site = serde_json::from_value(json).unwrap();
        assert_eq!(site.id, "s2");
        assert!(site.display_name.is_none());
        assert!(site.description.is_none());
        assert!(site.created_at.is_none());
        assert!(site.last_modified_at.is_none());
    }

    #[test]
    fn site_clone() {
        let site = Site {
            id: "clone-1".into(),
            name: "Clone Site".into(),
            display_name: None,
            web_url: "https://example.com".into(),
            description: None,
            created_at: None,
            last_modified_at: None,
        };
        let cloned = site.clone();
        assert_eq!(cloned.id, site.id);
        assert_eq!(cloned.name, site.name);
    }

    #[test]
    fn site_debug() {
        let site = Site {
            id: "dbg-1".into(),
            name: "Debug".into(),
            display_name: None,
            web_url: "https://example.com".into(),
            description: None,
            created_at: None,
            last_modified_at: None,
        };
        let debug = format!("{site:?}");
        assert!(debug.contains("Site"), "got: {debug}");
        assert!(debug.contains("dbg-1"), "got: {debug}");
    }

    // ====================================================================
    // DriveType
    // ====================================================================

    #[test]
    fn drive_type_serde_personal() {
        let dt = DriveType::Personal;
        let json = serde_json::to_value(dt).unwrap();
        assert_eq!(json, "personal");
        let back: DriveType = serde_json::from_value(json).unwrap();
        assert_eq!(back, DriveType::Personal);
    }

    #[test]
    fn drive_type_serde_business() {
        let dt = DriveType::Business;
        let json = serde_json::to_value(dt).unwrap();
        assert_eq!(json, "business");
        let back: DriveType = serde_json::from_value(json).unwrap();
        assert_eq!(back, DriveType::Business);
    }

    #[test]
    fn drive_type_serde_document_library() {
        let dt = DriveType::DocumentLibrary;
        let json = serde_json::to_value(dt).unwrap();
        assert_eq!(json, "documentLibrary");
        let back: DriveType = serde_json::from_value(json).unwrap();
        assert_eq!(back, DriveType::DocumentLibrary);
    }

    #[test]
    fn drive_type_unknown_fallback() {
        let json = serde_json::json!("somethingElse");
        let dt: DriveType = serde_json::from_value(json).unwrap();
        assert_eq!(dt, DriveType::Unknown);
    }

    #[test]
    fn drive_type_display() {
        assert_eq!(DriveType::Personal.to_string(), "personal");
        assert_eq!(DriveType::Business.to_string(), "business");
        assert_eq!(DriveType::DocumentLibrary.to_string(), "documentLibrary");
        assert_eq!(DriveType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn drive_type_clone_and_copy() {
        let dt = DriveType::Business;
        let copied = dt;
        let also_copied = dt;
        assert_eq!(copied, also_copied);
    }

    // ====================================================================
    // DriveQuota & QuotaState
    // ====================================================================

    #[test]
    fn drive_quota_serde_roundtrip() {
        let q = DriveQuota {
            used_bytes: 500_000,
            total_bytes: 1_000_000,
            remaining_bytes: 500_000,
            state: QuotaState::Normal,
        };
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(json["used"], 500_000);
        assert_eq!(json["total"], 1_000_000);
        assert_eq!(json["remaining"], 500_000);
        assert_eq!(json["state"], "normal");
        let back: DriveQuota = serde_json::from_value(json).unwrap();
        assert_eq!(back.used_bytes, 500_000);
        assert_eq!(back.state, QuotaState::Normal);
    }

    #[test]
    fn drive_quota_usage_fraction_normal() {
        let q = DriveQuota {
            used_bytes: 750_000,
            total_bytes: 1_000_000,
            remaining_bytes: 250_000,
            state: QuotaState::Nearing,
        };
        let frac = q.usage_fraction();
        assert!((frac - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn drive_quota_usage_fraction_zero_total() {
        let q = DriveQuota {
            used_bytes: 0,
            total_bytes: 0,
            remaining_bytes: 0,
            state: QuotaState::Normal,
        };
        assert!((q.usage_fraction()).abs() < f64::EPSILON);
    }

    #[test]
    fn drive_quota_usage_fraction_full() {
        let q = DriveQuota {
            used_bytes: 1_000_000,
            total_bytes: 1_000_000,
            remaining_bytes: 0,
            state: QuotaState::Exceeded,
        };
        assert!((q.usage_fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn drive_quota_clone() {
        let q = DriveQuota {
            used_bytes: 100,
            total_bytes: 200,
            remaining_bytes: 100,
            state: QuotaState::Normal,
        };
        let cloned = q.clone();
        assert_eq!(cloned.used_bytes, q.used_bytes);
        assert_eq!(cloned.state, q.state);
    }

    #[test]
    fn drive_quota_debug() {
        let q = DriveQuota {
            used_bytes: 42,
            total_bytes: 100,
            remaining_bytes: 58,
            state: QuotaState::Normal,
        };
        let debug = format!("{q:?}");
        assert!(debug.contains("DriveQuota"), "got: {debug}");
    }

    #[test]
    fn quota_state_serde_all_variants() {
        for (state, expected) in [
            (QuotaState::Normal, "normal"),
            (QuotaState::Nearing, "nearing"),
            (QuotaState::Critical, "critical"),
            (QuotaState::Exceeded, "exceeded"),
        ] {
            let json = serde_json::to_value(state).unwrap();
            assert_eq!(json, expected);
            let back: QuotaState = serde_json::from_value(json).unwrap();
            assert_eq!(back, state);
        }
    }

    #[test]
    fn quota_state_display() {
        assert_eq!(QuotaState::Normal.to_string(), "normal");
        assert_eq!(QuotaState::Nearing.to_string(), "nearing");
        assert_eq!(QuotaState::Critical.to_string(), "critical");
        assert_eq!(QuotaState::Exceeded.to_string(), "exceeded");
    }

    // ====================================================================
    // Drive
    // ====================================================================

    #[test]
    fn drive_serde_roundtrip() {
        let drive = Drive {
            id: "drv-1".into(),
            name: "Documents".into(),
            drive_type: DriveType::DocumentLibrary,
            owner: Some("Alice".into()),
            quota: Some(DriveQuota {
                used_bytes: 1024,
                total_bytes: 10240,
                remaining_bytes: 9216,
                state: QuotaState::Normal,
            }),
        };
        let json = serde_json::to_value(&drive).unwrap();
        assert_eq!(json["id"], "drv-1");
        assert_eq!(json["driveType"], "documentLibrary");
        assert_eq!(json["quota"]["used"], 1024);
        let back: Drive = serde_json::from_value(json).unwrap();
        assert_eq!(back.owner.as_deref(), Some("Alice"));
        assert!(back.quota.is_some());
    }

    #[test]
    fn drive_without_quota() {
        let json = serde_json::json!({
            "id": "drv-2",
            "name": "Shared",
            "driveType": "business"
        });
        let drive: Drive = serde_json::from_value(json).unwrap();
        assert!(drive.quota.is_none());
        assert!(drive.owner.is_none());
        assert_eq!(drive.drive_type, DriveType::Business);
    }

    #[test]
    fn drive_clone() {
        let drive = Drive {
            id: "clone-drv".into(),
            name: "Clone Drive".into(),
            drive_type: DriveType::Personal,
            owner: None,
            quota: None,
        };
        let cloned = drive.clone();
        assert_eq!(cloned.id, drive.id);
        assert_eq!(cloned.drive_type, drive.drive_type);
    }

    #[test]
    fn drive_debug() {
        let drive = Drive {
            id: "dbg".into(),
            name: "Debug Drive".into(),
            drive_type: DriveType::Unknown,
            owner: None,
            quota: None,
        };
        let debug = format!("{drive:?}");
        assert!(debug.contains("Drive"), "got: {debug}");
    }

    // ====================================================================
    // DriveItem
    // ====================================================================

    #[test]
    fn drive_item_file_serde() {
        let item = DriveItem {
            id: "item-1".into(),
            name: "report.docx".into(),
            size_bytes: Some(50_000),
            mime_type: Some(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document".into(),
            ),
            web_url: Some("https://contoso.sharepoint.com/sites/eng/report.docx".into()),
            created_at: Some("2026-01-15T10:00:00Z".into()),
            modified_at: Some("2026-03-01T14:00:00Z".into()),
            modified_by: Some("Bob".into()),
            is_folder: false,
            parent_path: Some("/sites/eng/Documents".into()),
        };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["id"], "item-1");
        assert_eq!(json["name"], "report.docx");
        assert_eq!(json["size"], 50_000);
        assert_eq!(json["isFolder"], false);
        let back: DriveItem = serde_json::from_value(json).unwrap();
        assert_eq!(
            back.mime_type.as_deref(),
            Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        );
    }

    #[test]
    fn drive_item_folder_serde() {
        let item = DriveItem {
            id: "folder-1".into(),
            name: "Documents".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: true,
            parent_path: Some("/sites/eng".into()),
        };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["isFolder"], true);
        let back: DriveItem = serde_json::from_value(json).unwrap();
        assert!(back.is_folder);
        assert!(!back.is_document());
    }

    #[test]
    fn drive_item_is_document() {
        let file = DriveItem {
            id: "f".into(),
            name: "test.txt".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        assert!(file.is_document());

        let folder = DriveItem {
            id: "d".into(),
            name: "folder".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: true,
            parent_path: None,
        };
        assert!(!folder.is_document());
    }

    #[test]
    fn drive_item_file_extension_docx() {
        let item = DriveItem {
            id: "ext-1".into(),
            name: "report.docx".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        assert_eq!(item.file_extension(), Some("docx"));
    }

    #[test]
    fn drive_item_file_extension_multiple_dots() {
        let item = DriveItem {
            id: "ext-2".into(),
            name: "archive.tar.gz".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        assert_eq!(item.file_extension(), Some("gz"));
    }

    #[test]
    fn drive_item_file_extension_no_extension() {
        let item = DriveItem {
            id: "ext-3".into(),
            name: "Makefile".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        assert!(item.file_extension().is_none());
    }

    #[test]
    fn drive_item_file_extension_folder_returns_none() {
        let item = DriveItem {
            id: "ext-4".into(),
            name: "folder.docs".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: true,
            parent_path: None,
        };
        assert!(item.file_extension().is_none());
    }

    #[test]
    fn drive_item_file_extension_dot_only() {
        let item = DriveItem {
            id: "ext-5".into(),
            name: ".gitignore".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        // ".gitignore" -> ext is "gitignore" which equals length, so returns None
        // Actually: rsplit('.') -> ["gitignore", ""], ext = "gitignore", len=9, name.len()=10, so Some("gitignore")
        assert_eq!(item.file_extension(), Some("gitignore"));
    }

    #[test]
    fn drive_item_clone() {
        let item = DriveItem {
            id: "clone".into(),
            name: "clone.txt".into(),
            size_bytes: Some(100),
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        let cloned = item.clone();
        assert_eq!(cloned.id, item.id);
        assert_eq!(cloned.size_bytes, item.size_bytes);
    }

    #[test]
    fn drive_item_debug() {
        let item = DriveItem {
            id: "dbg".into(),
            name: "debug.txt".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        let debug = format!("{item:?}");
        assert!(debug.contains("DriveItem"), "got: {debug}");
    }

    // ====================================================================
    // SharePointList
    // ====================================================================

    #[test]
    fn sharepoint_list_serde_roundtrip() {
        let list = SharePointList {
            id: "list-1".into(),
            name: "tasks".into(),
            display_name: Some("Team Tasks".into()),
            description: Some("Tracking work items".into()),
            item_count: Some(42),
            list_type: "genericList".into(),
        };
        let json = serde_json::to_value(&list).unwrap();
        assert_eq!(json["id"], "list-1");
        assert_eq!(json["displayName"], "Team Tasks");
        assert_eq!(json["itemCount"], 42);
        assert_eq!(json["listType"], "genericList");
        let back: SharePointList = serde_json::from_value(json).unwrap();
        assert_eq!(back.description.as_deref(), Some("Tracking work items"));
    }

    #[test]
    fn sharepoint_list_optional_fields() {
        let json = serde_json::json!({
            "id": "list-2",
            "name": "docs",
            "listType": "documentLibrary"
        });
        let list: SharePointList = serde_json::from_value(json).unwrap();
        assert!(list.display_name.is_none());
        assert!(list.description.is_none());
        assert!(list.item_count.is_none());
    }

    #[test]
    fn sharepoint_list_clone() {
        let list = SharePointList {
            id: "cl".into(),
            name: "cl".into(),
            display_name: None,
            description: None,
            item_count: Some(10),
            list_type: "events".into(),
        };
        let cloned = list.clone();
        assert_eq!(cloned.item_count, list.item_count);
    }

    #[test]
    fn sharepoint_list_debug() {
        let list = SharePointList {
            id: "dbg".into(),
            name: "dbg".into(),
            display_name: None,
            description: None,
            item_count: None,
            list_type: "generic".into(),
        };
        let debug = format!("{list:?}");
        assert!(debug.contains("SharePointList"), "got: {debug}");
    }

    // ====================================================================
    // SearchEntityType
    // ====================================================================

    #[test]
    fn search_entity_type_serde_all_variants() {
        for (et, expected) in [
            (SearchEntityType::DriveItem, "driveItem"),
            (SearchEntityType::ListItem, "listItem"),
            (SearchEntityType::Site, "site"),
            (SearchEntityType::Message, "message"),
        ] {
            let json = serde_json::to_value(et).unwrap();
            assert_eq!(json, expected);
            let back: SearchEntityType = serde_json::from_value(json).unwrap();
            assert_eq!(back, et);
        }
    }

    #[test]
    fn search_entity_type_display() {
        assert_eq!(SearchEntityType::DriveItem.to_string(), "driveItem");
        assert_eq!(SearchEntityType::ListItem.to_string(), "listItem");
        assert_eq!(SearchEntityType::Site.to_string(), "site");
        assert_eq!(SearchEntityType::Message.to_string(), "message");
    }

    #[test]
    fn search_entity_type_clone_copy() {
        let et = SearchEntityType::Site;
        let copied = et;
        let also_copied = et;
        assert_eq!(copied, also_copied);
    }

    // ====================================================================
    // SearchQuery
    // ====================================================================

    #[test]
    fn search_query_builder_basic() {
        let q = SearchQuery::new("budget report")
            .with_entity_type(SearchEntityType::DriveItem)
            .with_limit(10)
            .with_offset(5);
        assert_eq!(q.query, "budget report");
        assert_eq!(q.entity_types.len(), 1);
        assert_eq!(q.limit, 10);
        assert_eq!(q.offset, 5);
        assert!(q.from_site.is_none());
        assert!(q.validate().is_ok());
    }

    #[test]
    fn search_query_builder_with_site() {
        let q = SearchQuery::new("memo")
            .with_entity_type(SearchEntityType::ListItem)
            .from_site("site-123");
        assert_eq!(q.from_site.as_deref(), Some("site-123"));
        assert!(q.validate().is_ok());
    }

    #[test]
    fn search_query_builder_multiple_entity_types() {
        let q = SearchQuery::new("sales")
            .with_entity_type(SearchEntityType::DriveItem)
            .with_entity_type(SearchEntityType::Site)
            .with_entity_type(SearchEntityType::DriveItem); // duplicate
        assert_eq!(q.entity_types.len(), 2);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn search_query_validate_empty() {
        let q = SearchQuery::new("").with_entity_type(SearchEntityType::DriveItem);
        assert_eq!(q.validate(), Err(SearchValidationError::EmptyQuery));
    }

    #[test]
    fn search_query_validate_whitespace_only() {
        let q = SearchQuery::new("   ").with_entity_type(SearchEntityType::Site);
        assert_eq!(q.validate(), Err(SearchValidationError::EmptyQuery));
    }

    #[test]
    fn search_query_validate_no_entity_types() {
        let q = SearchQuery::new("test");
        assert_eq!(q.validate(), Err(SearchValidationError::NoEntityTypes));
    }

    #[test]
    fn search_query_validate_limit_too_high() {
        let q = SearchQuery::new("test")
            .with_entity_type(SearchEntityType::DriveItem)
            .with_limit(200);
        assert_eq!(q.validate(), Err(SearchValidationError::LimitTooHigh(200)));
    }

    #[test]
    fn search_query_validate_limit_at_max() {
        let q = SearchQuery::new("ok")
            .with_entity_type(SearchEntityType::Message)
            .with_limit(SearchQuery::MAX_LIMIT);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn search_query_defaults() {
        let q = SearchQuery::new("hello");
        assert_eq!(q.limit, SearchQuery::DEFAULT_LIMIT);
        assert_eq!(q.offset, 0);
        assert!(q.entity_types.is_empty());
        assert!(q.from_site.is_none());
    }

    #[test]
    fn search_query_serde_roundtrip() {
        let q = SearchQuery::new("roundtrip")
            .with_entity_type(SearchEntityType::Site)
            .with_limit(50)
            .with_offset(10)
            .from_site("site-rt");
        let json = serde_json::to_value(&q).unwrap();
        let back: SearchQuery = serde_json::from_value(json).unwrap();
        assert_eq!(back.query, "roundtrip");
        assert_eq!(back.limit, 50);
        assert_eq!(back.offset, 10);
        assert_eq!(back.from_site.as_deref(), Some("site-rt"));
    }

    #[test]
    fn search_query_clone() {
        let q = SearchQuery::new("clone").with_entity_type(SearchEntityType::DriveItem);
        let cloned = q.clone();
        assert_eq!(cloned.query, q.query);
        assert_eq!(cloned.entity_types.len(), q.entity_types.len());
    }

    #[test]
    fn search_query_debug() {
        let q = SearchQuery::new("debug");
        let debug = format!("{q:?}");
        assert!(debug.contains("SearchQuery"), "got: {debug}");
    }

    // ====================================================================
    // SearchValidationError
    // ====================================================================

    #[test]
    fn search_validation_error_display() {
        assert!(
            SearchValidationError::EmptyQuery
                .to_string()
                .contains("empty")
        );
        assert!(
            SearchValidationError::LimitTooHigh(150)
                .to_string()
                .contains("150")
        );
        assert!(
            SearchValidationError::NoEntityTypes
                .to_string()
                .contains("entity type")
        );
    }

    #[test]
    fn search_validation_error_eq() {
        assert_eq!(
            SearchValidationError::EmptyQuery,
            SearchValidationError::EmptyQuery
        );
        assert_eq!(
            SearchValidationError::LimitTooHigh(100),
            SearchValidationError::LimitTooHigh(100)
        );
        assert_ne!(
            SearchValidationError::EmptyQuery,
            SearchValidationError::NoEntityTypes
        );
    }

    // ====================================================================
    // SearchResult & SearchResults
    // ====================================================================

    #[test]
    fn search_result_serde() {
        let r = SearchResult {
            id: "sr-1".into(),
            name: "Budget.xlsx".into(),
            summary: Some("Q4 budget spreadsheet".into()),
            web_url: Some("https://contoso.sharepoint.com/budget.xlsx".into()),
            entity_type: SearchEntityType::DriveItem,
            hit_highlights: vec!["<b>budget</b> overview".into()],
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["id"], "sr-1");
        assert_eq!(json["entity_type"], "driveItem");
        let back: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.hit_highlights.len(), 1);
    }

    #[test]
    fn search_result_no_highlights() {
        let r = SearchResult {
            id: "sr-2".into(),
            name: "Notes".into(),
            summary: None,
            web_url: None,
            entity_type: SearchEntityType::Site,
            hit_highlights: vec![],
        };
        let json = serde_json::to_value(&r).unwrap();
        let back: SearchResult = serde_json::from_value(json).unwrap();
        assert!(back.hit_highlights.is_empty());
        assert!(back.summary.is_none());
    }

    #[test]
    fn search_result_clone() {
        let r = SearchResult {
            id: "cl".into(),
            name: "Clone".into(),
            summary: Some("test".into()),
            web_url: None,
            entity_type: SearchEntityType::ListItem,
            hit_highlights: vec!["hl".into()],
        };
        let cloned = r.clone();
        assert_eq!(cloned.id, r.id);
        assert_eq!(cloned.hit_highlights.len(), r.hit_highlights.len());
    }

    #[test]
    fn search_result_debug() {
        let r = SearchResult {
            id: "dbg".into(),
            name: "Debug".into(),
            summary: None,
            web_url: None,
            entity_type: SearchEntityType::Message,
            hit_highlights: vec![],
        };
        let debug = format!("{r:?}");
        assert!(debug.contains("SearchResult"), "got: {debug}");
    }

    #[test]
    fn search_results_empty() {
        let sr = SearchResults::empty();
        assert!(sr.results.is_empty());
        assert_eq!(sr.total_estimated, 0);
        assert!(!sr.has_more);
        assert_eq!(sr.count(), 0);
    }

    #[test]
    fn search_results_with_items() {
        let sr = SearchResults {
            results: vec![
                SearchResult {
                    id: "a".into(),
                    name: "A".into(),
                    summary: None,
                    web_url: None,
                    entity_type: SearchEntityType::DriveItem,
                    hit_highlights: vec![],
                },
                SearchResult {
                    id: "b".into(),
                    name: "B".into(),
                    summary: None,
                    web_url: None,
                    entity_type: SearchEntityType::Site,
                    hit_highlights: vec![],
                },
            ],
            total_estimated: 50,
            has_more: true,
        };
        assert_eq!(sr.count(), 2);
        assert_eq!(sr.total_estimated, 50);
        assert!(sr.has_more);
    }

    #[test]
    fn search_results_serde_roundtrip() {
        let sr = SearchResults {
            results: vec![SearchResult {
                id: "rt".into(),
                name: "RT".into(),
                summary: Some("roundtrip".into()),
                web_url: None,
                entity_type: SearchEntityType::ListItem,
                hit_highlights: vec!["<b>rt</b>".into()],
            }],
            total_estimated: 1,
            has_more: false,
        };
        let json = serde_json::to_value(&sr).unwrap();
        let back: SearchResults = serde_json::from_value(json).unwrap();
        assert_eq!(back.count(), 1);
        assert_eq!(back.total_estimated, 1);
    }

    #[test]
    fn search_results_clone() {
        let sr = SearchResults::empty();
        let cloned = sr.clone();
        assert_eq!(cloned.count(), sr.count());
    }

    #[test]
    fn search_results_debug() {
        let sr = SearchResults::empty();
        let debug = format!("{sr:?}");
        assert!(debug.contains("SearchResults"), "got: {debug}");
    }

    // ====================================================================
    // SharingLinkType
    // ====================================================================

    #[test]
    fn sharing_link_type_serde_all() {
        for (lt, expected) in [
            (SharingLinkType::View, "view"),
            (SharingLinkType::Edit, "edit"),
            (SharingLinkType::Embed, "embed"),
        ] {
            let json = serde_json::to_value(lt).unwrap();
            assert_eq!(json, expected);
            let back: SharingLinkType = serde_json::from_value(json).unwrap();
            assert_eq!(back, lt);
        }
    }

    #[test]
    fn sharing_link_type_display() {
        assert_eq!(SharingLinkType::View.to_string(), "view");
        assert_eq!(SharingLinkType::Edit.to_string(), "edit");
        assert_eq!(SharingLinkType::Embed.to_string(), "embed");
    }

    #[test]
    fn sharing_link_type_clone_copy() {
        let lt = SharingLinkType::Edit;
        let copied = lt;
        let also_copied = lt;
        assert_eq!(copied, also_copied);
    }

    // ====================================================================
    // SharingScope
    // ====================================================================

    #[test]
    fn sharing_scope_serde_all() {
        for (s, expected) in [
            (SharingScope::Anonymous, "anonymous"),
            (SharingScope::Organization, "organization"),
            (SharingScope::SpecificPeople, "specificPeople"),
        ] {
            let json = serde_json::to_value(s).unwrap();
            assert_eq!(json, expected);
            let back: SharingScope = serde_json::from_value(json).unwrap();
            assert_eq!(back, s);
        }
    }

    #[test]
    fn sharing_scope_display() {
        assert_eq!(SharingScope::Anonymous.to_string(), "anonymous");
        assert_eq!(SharingScope::Organization.to_string(), "organization");
        assert_eq!(SharingScope::SpecificPeople.to_string(), "specificPeople");
    }

    // ====================================================================
    // SharingLink
    // ====================================================================

    #[test]
    fn sharing_link_serde_roundtrip() {
        let link = SharingLink {
            link_id: Some("lnk-1".into()),
            link_type: SharingLinkType::View,
            scope: SharingScope::Organization,
            web_url: Some("https://contoso.sharepoint.com/share/abc".into()),
            expiration: Some("2026-12-31T23:59:59Z".into()),
        };
        let json = serde_json::to_value(&link).unwrap();
        assert_eq!(json["link_type"], "view");
        assert_eq!(json["scope"], "organization");
        let back: SharingLink = serde_json::from_value(json).unwrap();
        assert_eq!(back.link_id.as_deref(), Some("lnk-1"));
        assert_eq!(back.expiration.as_deref(), Some("2026-12-31T23:59:59Z"));
    }

    #[test]
    fn sharing_link_is_writable() {
        let view = SharingLink {
            link_id: None,
            link_type: SharingLinkType::View,
            scope: SharingScope::Anonymous,
            web_url: None,
            expiration: None,
        };
        assert!(!view.is_writable());

        let edit = SharingLink {
            link_id: None,
            link_type: SharingLinkType::Edit,
            scope: SharingScope::Organization,
            web_url: None,
            expiration: None,
        };
        assert!(edit.is_writable());

        let embed = SharingLink {
            link_id: None,
            link_type: SharingLinkType::Embed,
            scope: SharingScope::SpecificPeople,
            web_url: None,
            expiration: None,
        };
        assert!(!embed.is_writable());
    }

    #[test]
    fn sharing_link_is_public() {
        let public = SharingLink {
            link_id: None,
            link_type: SharingLinkType::View,
            scope: SharingScope::Anonymous,
            web_url: None,
            expiration: None,
        };
        assert!(public.is_public());

        let org = SharingLink {
            link_id: None,
            link_type: SharingLinkType::View,
            scope: SharingScope::Organization,
            web_url: None,
            expiration: None,
        };
        assert!(!org.is_public());

        let specific = SharingLink {
            link_id: None,
            link_type: SharingLinkType::View,
            scope: SharingScope::SpecificPeople,
            web_url: None,
            expiration: None,
        };
        assert!(!specific.is_public());
    }

    #[test]
    fn sharing_link_optional_fields() {
        let json = serde_json::json!({
            "link_type": "embed",
            "scope": "anonymous"
        });
        let link: SharingLink = serde_json::from_value(json).unwrap();
        assert!(link.link_id.is_none());
        assert!(link.web_url.is_none());
        assert!(link.expiration.is_none());
    }

    #[test]
    fn sharing_link_clone() {
        let link = SharingLink {
            link_id: Some("cl".into()),
            link_type: SharingLinkType::Edit,
            scope: SharingScope::Organization,
            web_url: Some("https://example.com".into()),
            expiration: None,
        };
        let cloned = link.clone();
        assert_eq!(cloned.link_id, link.link_id);
        assert_eq!(cloned.link_type, link.link_type);
    }

    #[test]
    fn sharing_link_debug() {
        let link = SharingLink {
            link_id: None,
            link_type: SharingLinkType::View,
            scope: SharingScope::Anonymous,
            web_url: None,
            expiration: None,
        };
        let debug = format!("{link:?}");
        assert!(debug.contains("SharingLink"), "got: {debug}");
    }

    // ====================================================================
    // SharePointAction
    // ====================================================================

    #[test]
    fn sharepoint_action_display() {
        assert_eq!(SharePointAction::Read.to_string(), "read");
        assert_eq!(SharePointAction::Write.to_string(), "write");
        assert_eq!(SharePointAction::Search.to_string(), "search");
        assert_eq!(SharePointAction::Share.to_string(), "share");
    }

    #[test]
    fn sharepoint_action_eq() {
        assert_eq!(SharePointAction::Read, SharePointAction::Read);
        assert_ne!(SharePointAction::Read, SharePointAction::Write);
    }

    // ====================================================================
    // PolicyDecision
    // ====================================================================

    #[test]
    fn policy_decision_allow() {
        let d = PolicyDecision::Allow;
        assert!(d.is_allowed());
        assert!(!d.requires_approval());
        assert!(!d.is_denied());
    }

    #[test]
    fn policy_decision_requires_approval() {
        let d = PolicyDecision::RequiresApproval;
        assert!(d.is_allowed());
        assert!(d.requires_approval());
        assert!(!d.is_denied());
    }

    #[test]
    fn policy_decision_deny() {
        let d = PolicyDecision::Deny("nope".into());
        assert!(!d.is_allowed());
        assert!(!d.requires_approval());
        assert!(d.is_denied());
    }

    #[test]
    fn policy_decision_eq() {
        assert_eq!(PolicyDecision::Allow, PolicyDecision::Allow);
        assert_eq!(
            PolicyDecision::RequiresApproval,
            PolicyDecision::RequiresApproval
        );
        assert_eq!(
            PolicyDecision::Deny("x".into()),
            PolicyDecision::Deny("x".into())
        );
        assert_ne!(PolicyDecision::Allow, PolicyDecision::RequiresApproval);
    }

    #[test]
    fn policy_decision_clone() {
        let d = PolicyDecision::Deny("reason".into());
        let cloned = d.clone();
        assert_eq!(cloned, d);
    }

    // ====================================================================
    // SharePointPolicy
    // ====================================================================

    #[test]
    fn policy_default_denies_all() {
        let p = SharePointPolicy::default();
        assert!(!p.allow_read);
        assert!(!p.allow_write);
        assert!(!p.allow_search);
        assert!(!p.allow_share);
        assert!(p.require_approval_for_write);
        assert!(p.require_approval_for_share);
        assert!(p.blocked_sites.is_empty());
    }

    #[test]
    fn policy_new_is_default() {
        let p = SharePointPolicy::new();
        assert!(!p.allow_read);
        assert!(!p.allow_write);
    }

    #[test]
    fn policy_permissive_allows_all() {
        let p = SharePointPolicy::new_permissive();
        assert!(p.allow_read);
        assert!(p.allow_write);
        assert!(p.allow_search);
        assert!(p.allow_share);
        assert!(!p.require_approval_for_write);
        assert!(!p.require_approval_for_share);
    }

    #[test]
    fn policy_readonly() {
        let p = SharePointPolicy::new_readonly();
        assert!(p.allow_read);
        assert!(!p.allow_write);
        assert!(p.allow_search);
        assert!(!p.allow_share);
        assert_eq!(p.max_upload_bytes, 0);
    }

    #[test]
    fn policy_check_read_allowed() {
        let p = SharePointPolicy::new_readonly();
        let d = p.check_action(SharePointAction::Read, None);
        assert_eq!(d, PolicyDecision::Allow);
    }

    #[test]
    fn policy_check_read_denied() {
        let p = SharePointPolicy::default();
        let d = p.check_action(SharePointAction::Read, None);
        assert!(d.is_denied());
    }

    #[test]
    fn policy_check_write_allowed_no_approval() {
        let p = SharePointPolicy::new_permissive();
        let d = p.check_action(SharePointAction::Write, None);
        assert_eq!(d, PolicyDecision::Allow);
    }

    #[test]
    fn policy_check_write_requires_approval() {
        let mut p = SharePointPolicy::new_permissive();
        p.require_approval_for_write = true;
        let d = p.check_action(SharePointAction::Write, None);
        assert_eq!(d, PolicyDecision::RequiresApproval);
    }

    #[test]
    fn policy_check_write_denied() {
        let p = SharePointPolicy::new_readonly();
        let d = p.check_action(SharePointAction::Write, None);
        assert!(d.is_denied());
    }

    #[test]
    fn policy_check_search_allowed() {
        let p = SharePointPolicy::new_readonly();
        let d = p.check_action(SharePointAction::Search, None);
        assert_eq!(d, PolicyDecision::Allow);
    }

    #[test]
    fn policy_check_search_denied() {
        let p = SharePointPolicy::default();
        let d = p.check_action(SharePointAction::Search, None);
        assert!(d.is_denied());
    }

    #[test]
    fn policy_check_share_allowed_no_approval() {
        let p = SharePointPolicy::new_permissive();
        let d = p.check_action(SharePointAction::Share, None);
        assert_eq!(d, PolicyDecision::Allow);
    }

    #[test]
    fn policy_check_share_requires_approval() {
        let mut p = SharePointPolicy::new_permissive();
        p.require_approval_for_share = true;
        let d = p.check_action(SharePointAction::Share, None);
        assert_eq!(d, PolicyDecision::RequiresApproval);
    }

    #[test]
    fn policy_check_share_denied() {
        let p = SharePointPolicy::default();
        let d = p.check_action(SharePointAction::Share, None);
        assert!(d.is_denied());
    }

    #[test]
    fn policy_blocked_site_overrides_allow() {
        let mut p = SharePointPolicy::new_permissive();
        p.blocked_sites.insert("bad-site".into());
        let d = p.check_action(SharePointAction::Read, Some("bad-site"));
        assert!(d.is_denied());
        if let PolicyDecision::Deny(msg) = d {
            assert!(msg.contains("bad-site"));
        }
    }

    #[test]
    fn policy_blocked_site_nonblocked_passes() {
        let mut p = SharePointPolicy::new_permissive();
        p.blocked_sites.insert("bad-site".into());
        let d = p.check_action(SharePointAction::Read, Some("good-site"));
        assert_eq!(d, PolicyDecision::Allow);
    }

    #[test]
    fn policy_blocked_site_none_site() {
        let mut p = SharePointPolicy::new_permissive();
        p.blocked_sites.insert("bad-site".into());
        let d = p.check_action(SharePointAction::Read, None);
        assert_eq!(d, PolicyDecision::Allow);
    }

    #[test]
    fn policy_check_upload_size_within_limit() {
        let p = SharePointPolicy::new_permissive();
        assert!(p.check_upload_size(100));
        assert!(p.check_upload_size(p.max_upload_bytes));
    }

    #[test]
    fn policy_check_upload_size_exceeds_limit() {
        let p = SharePointPolicy::new_permissive();
        assert!(!p.check_upload_size(p.max_upload_bytes + 1));
    }

    #[test]
    fn policy_check_upload_size_zero_limit() {
        let p = SharePointPolicy::new_readonly();
        assert!(p.check_upload_size(0));
        assert!(!p.check_upload_size(1));
    }

    #[test]
    fn policy_clone() {
        let mut p = SharePointPolicy::new_permissive();
        p.blocked_sites.insert("x".into());
        let cloned = p.clone();
        assert_eq!(cloned.allow_read, p.allow_read);
        assert!(cloned.blocked_sites.contains("x"));
    }

    #[test]
    fn policy_debug() {
        let p = SharePointPolicy::default();
        let debug = format!("{p:?}");
        assert!(debug.contains("SharePointPolicy"), "got: {debug}");
    }

    // ====================================================================
    // SharePointAuditEvent
    // ====================================================================

    #[test]
    fn audit_event_new() {
        let e = SharePointAuditEvent::new("write", "uploaded file");
        assert_eq!(e.action, "write");
        assert_eq!(e.details, "uploaded file");
        assert!(e.site_id.is_none());
        assert!(e.item_path.is_none());
    }

    #[test]
    fn audit_event_builder() {
        let e = SharePointAuditEvent::new("share", "created link")
            .with_site("site-1")
            .with_item("/docs/report.pdf");
        assert_eq!(e.site_id.as_deref(), Some("site-1"));
        assert_eq!(e.item_path.as_deref(), Some("/docs/report.pdf"));
    }

    #[test]
    fn audit_event_summary_full() {
        let e = SharePointAuditEvent::new("write", "uploaded 5MB file")
            .with_site("eng-site")
            .with_item("/documents/data.xlsx");
        let s = e.summary();
        assert!(s.contains("write"), "got: {s}");
        assert!(s.contains("eng-site"), "got: {s}");
        assert!(s.contains("/documents/data.xlsx"), "got: {s}");
        assert!(s.contains("uploaded 5MB file"), "got: {s}");
    }

    #[test]
    fn audit_event_summary_minimal() {
        let e = SharePointAuditEvent::new("read", "list sites");
        let s = e.summary();
        assert!(s.contains("read"), "got: {s}");
        assert!(s.contains("list sites"), "got: {s}");
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let e = SharePointAuditEvent::new("search", "searched for budget").with_site("finance");
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["action"], "search");
        assert_eq!(json["site_id"], "finance");
        let back: SharePointAuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back.action, "search");
        assert_eq!(back.site_id.as_deref(), Some("finance"));
    }

    #[test]
    fn audit_event_clone() {
        let e = SharePointAuditEvent::new("write", "test");
        let cloned = e.clone();
        assert_eq!(cloned.action, e.action);
        assert_eq!(cloned.details, e.details);
    }

    #[test]
    fn audit_event_debug() {
        let e = SharePointAuditEvent::new("read", "debug");
        let debug = format!("{e:?}");
        assert!(debug.contains("SharePointAuditEvent"), "got: {debug}");
    }

    // ====================================================================
    // URL helpers
    // ====================================================================

    #[test]
    fn url_sites() {
        assert_eq!(sites_url(), "https://graph.microsoft.com/v1.0/sites");
    }

    #[test]
    fn url_site() {
        assert_eq!(
            site_url("site-123"),
            "https://graph.microsoft.com/v1.0/sites/site-123"
        );
    }

    #[test]
    fn url_site_drives() {
        assert_eq!(
            site_drives_url("s1"),
            "https://graph.microsoft.com/v1.0/sites/s1/drives"
        );
    }

    #[test]
    fn url_drive_root_children() {
        assert_eq!(
            drive_root_children_url("s1", "d1"),
            "https://graph.microsoft.com/v1.0/sites/s1/drives/d1/root/children"
        );
    }

    #[test]
    fn url_drive_item() {
        assert_eq!(
            drive_item_url("s1", "d1", "item-1"),
            "https://graph.microsoft.com/v1.0/sites/s1/drives/d1/items/item-1"
        );
    }

    #[test]
    fn url_site_lists() {
        assert_eq!(
            site_lists_url("s1"),
            "https://graph.microsoft.com/v1.0/sites/s1/lists"
        );
    }

    #[test]
    fn url_search() {
        assert_eq!(
            search_url(),
            "https://graph.microsoft.com/v1.0/search/query"
        );
    }

    #[test]
    fn url_create_link() {
        assert_eq!(
            create_link_url("s1", "d1", "i1"),
            "https://graph.microsoft.com/v1.0/sites/s1/drives/d1/items/i1/createLink"
        );
    }

    // ====================================================================
    // Integration / cross-cutting tests
    // ====================================================================

    #[test]
    fn policy_gates_write_with_audit() {
        let policy = SharePointPolicy::new_readonly();
        let decision = policy.check_action(SharePointAction::Write, Some("site-42"));
        assert!(decision.is_denied());

        // Audit event should still be creatable for denied writes.
        let audit = SharePointAuditEvent::new("write_denied", "policy blocked write")
            .with_site("site-42")
            .with_item("/secret.docx");
        assert_eq!(audit.site_id.as_deref(), Some("site-42"));
    }

    #[test]
    fn policy_gates_share_with_audit() {
        let mut policy = SharePointPolicy::new_permissive();
        policy.require_approval_for_share = true;
        let decision = policy.check_action(SharePointAction::Share, None);
        assert!(decision.requires_approval());

        let audit =
            SharePointAuditEvent::new("share_pending_approval", "anonymous edit link requested")
                .with_item("/public/deck.pptx");
        assert!(audit.summary().contains("pending_approval"));
    }

    #[test]
    fn drive_item_extension_matches_mime() {
        let item = DriveItem {
            id: "doc-1".into(),
            name: "presentation.pptx".into(),
            size_bytes: Some(2_000_000),
            mime_type: Some(
                "application/vnd.openxmlformats-officedocument.presentationml.presentation".into(),
            ),
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        assert_eq!(item.file_extension(), Some("pptx"));
        assert!(item.is_document());
    }

    #[test]
    fn search_query_full_pipeline() {
        let query = SearchQuery::new("quarterly report")
            .with_entity_type(SearchEntityType::DriveItem)
            .with_entity_type(SearchEntityType::ListItem)
            .from_site("finance-site")
            .with_limit(50)
            .with_offset(0);
        assert!(query.validate().is_ok());

        // Simulate results.
        let results = SearchResults {
            results: vec![SearchResult {
                id: "hit-1".into(),
                name: "Q4 Report.xlsx".into(),
                summary: Some("Quarterly financial report".into()),
                web_url: Some("https://contoso.sharepoint.com/q4.xlsx".into()),
                entity_type: SearchEntityType::DriveItem,
                hit_highlights: vec!["<b>quarterly</b> <b>report</b>".into()],
            }],
            total_estimated: 1,
            has_more: false,
        };
        assert_eq!(results.count(), 1);
        assert!(!results.has_more);
    }

    #[test]
    fn sharing_link_public_writable_checks() {
        let link = SharingLink {
            link_id: Some("lnk-pub-edit".into()),
            link_type: SharingLinkType::Edit,
            scope: SharingScope::Anonymous,
            web_url: Some("https://contoso.sharepoint.com/share/xyz".into()),
            expiration: None,
        };
        assert!(link.is_writable());
        assert!(link.is_public());
    }

    #[test]
    fn sharing_link_org_view_checks() {
        let link = SharingLink {
            link_id: None,
            link_type: SharingLinkType::View,
            scope: SharingScope::Organization,
            web_url: None,
            expiration: Some("2026-06-01T00:00:00Z".into()),
        };
        assert!(!link.is_writable());
        assert!(!link.is_public());
    }

    #[test]
    fn default_policy_blocks_all_actions() {
        let p = SharePointPolicy::default();
        for action in [
            SharePointAction::Read,
            SharePointAction::Write,
            SharePointAction::Search,
            SharePointAction::Share,
        ] {
            let d = p.check_action(action, None);
            assert!(d.is_denied(), "action {action} should be denied by default");
        }
    }

    #[test]
    fn permissive_policy_allows_all_actions() {
        let p = SharePointPolicy::new_permissive();
        for action in [
            SharePointAction::Read,
            SharePointAction::Write,
            SharePointAction::Search,
            SharePointAction::Share,
        ] {
            let d = p.check_action(action, None);
            assert_eq!(
                d,
                PolicyDecision::Allow,
                "action {action} should be allowed"
            );
        }
    }

    #[test]
    fn readonly_policy_allows_read_search_only() {
        let p = SharePointPolicy::new_readonly();
        assert_eq!(
            p.check_action(SharePointAction::Read, None),
            PolicyDecision::Allow
        );
        assert_eq!(
            p.check_action(SharePointAction::Search, None),
            PolicyDecision::Allow
        );
        assert!(p.check_action(SharePointAction::Write, None).is_denied());
        assert!(p.check_action(SharePointAction::Share, None).is_denied());
    }

    #[test]
    fn multiple_blocked_sites() {
        let mut p = SharePointPolicy::new_permissive();
        p.blocked_sites.insert("alpha".into());
        p.blocked_sites.insert("beta".into());
        p.blocked_sites.insert("gamma".into());

        assert!(
            p.check_action(SharePointAction::Read, Some("alpha"))
                .is_denied()
        );
        assert!(
            p.check_action(SharePointAction::Write, Some("beta"))
                .is_denied()
        );
        assert!(
            p.check_action(SharePointAction::Search, Some("gamma"))
                .is_denied()
        );
        assert_eq!(
            p.check_action(SharePointAction::Read, Some("delta")),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn drive_item_empty_name_no_extension() {
        let item = DriveItem {
            id: "e".into(),
            name: String::new(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        assert!(item.file_extension().is_none());
    }

    #[test]
    fn quota_state_critical_display() {
        let q = DriveQuota {
            used_bytes: 950,
            total_bytes: 1000,
            remaining_bytes: 50,
            state: QuotaState::Critical,
        };
        assert_eq!(q.state.to_string(), "critical");
        let frac = q.usage_fraction();
        assert!((frac - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn site_with_all_fields_serde() {
        let json = serde_json::json!({
            "id": "full-site",
            "name": "FullSite",
            "displayName": "Full Display Name",
            "webUrl": "https://contoso.sharepoint.com/sites/full",
            "description": "A site with all fields",
            "createdDateTime": "2025-06-01T00:00:00Z",
            "lastModifiedDateTime": "2026-02-15T12:00:00Z"
        });
        let site: Site = serde_json::from_value(json).unwrap();
        assert_eq!(site.description.as_deref(), Some("A site with all fields"));
        assert_eq!(site.created_at.as_deref(), Some("2025-06-01T00:00:00Z"));
        assert_eq!(
            site.last_modified_at.as_deref(),
            Some("2026-02-15T12:00:00Z")
        );
    }

    #[test]
    fn drive_item_trailing_dot_name() {
        let item = DriveItem {
            id: "td".into(),
            name: "file.".into(),
            size_bytes: None,
            mime_type: None,
            web_url: None,
            created_at: None,
            modified_at: None,
            modified_by: None,
            is_folder: false,
            parent_path: None,
        };
        // "file." -> rsplit('.') -> ["", "file"], ext = "", len=0, name.len()=5, Some("")
        assert_eq!(item.file_extension(), Some(""));
    }

    #[test]
    fn search_query_limit_one() {
        let q = SearchQuery::new("single")
            .with_entity_type(SearchEntityType::DriveItem)
            .with_limit(1);
        assert!(q.validate().is_ok());
        assert_eq!(q.limit, 1);
    }

    #[test]
    fn search_query_limit_zero() {
        let q = SearchQuery::new("zero")
            .with_entity_type(SearchEntityType::Site)
            .with_limit(0);
        assert!(q.validate().is_ok());
        assert_eq!(q.limit, 0);
    }

    #[test]
    fn policy_max_upload_default() {
        let p = SharePointPolicy::default();
        assert_eq!(p.max_upload_bytes, 250 * 1024 * 1024);
    }

    #[test]
    fn audit_event_with_item_only() {
        let e = SharePointAuditEvent::new("read", "downloaded").with_item("/path/to/file.pdf");
        let s = e.summary();
        assert!(s.contains("/path/to/file.pdf"), "got: {s}");
        assert!(e.site_id.is_none());
    }

    #[test]
    fn audit_event_with_site_only() {
        let e = SharePointAuditEvent::new("search", "queried").with_site("marketing");
        let s = e.summary();
        assert!(s.contains("marketing"), "got: {s}");
        assert!(e.item_path.is_none());
    }

    #[test]
    fn policy_decision_deny_different_reasons() {
        let d1 = PolicyDecision::Deny("reason a".into());
        let d2 = PolicyDecision::Deny("reason b".into());
        assert_ne!(d1, d2);
        assert!(d1.is_denied());
        assert!(d2.is_denied());
    }

    #[test]
    fn drive_quota_serde_exceeded_state() {
        let json = serde_json::json!({
            "used": 2000,
            "total": 1000,
            "remaining": 0,
            "state": "exceeded"
        });
        let q: DriveQuota = serde_json::from_value(json).unwrap();
        assert_eq!(q.state, QuotaState::Exceeded);
        assert_eq!(q.used_bytes, 2000);
    }

    #[test]
    fn sharing_scope_clone_copy() {
        let s = SharingScope::Organization;
        let copied = s;
        let also = s;
        assert_eq!(copied, also);
    }
}
