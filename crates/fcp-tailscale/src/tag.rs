//! Tailscale tag types and Zone ↔ tag mapping.
//!
//! FCP uses Tailscale ACL tags to map zone membership. Each zone is represented
//! by a tag with the format `tag:fcp-<zone-suffix>`.
//!
//! # Zone Mapping Convention
//!
//! | Zone ID      | Tailscale Tag      |
//! |--------------|-------------------|
//! | `z:owner`    | `tag:fcp-owner`   |
//! | `z:private`  | `tag:fcp-private` |
//! | `z:work`     | `tag:fcp-work`    |
//! | `z:community`| `tag:fcp-community`|
//! | `z:public`   | `tag:fcp-public`  |

use serde::{Deserialize, Serialize};

use crate::FCP_TAG_PREFIX;
use crate::error::{TailscaleError, TailscaleResult};

/// Tailscale ACL tag.
///
/// Tags are used for ACL-based access control in Tailscale. FCP uses tags
/// with the `tag:fcp-` prefix to represent zone membership.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TailscaleTag(String);

impl TailscaleTag {
    /// Create a new `TailscaleTag` from a string.
    ///
    /// The tag must start with `tag:` prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if the tag doesn't start with `tag:`.
    pub fn new(tag: impl Into<String>) -> TailscaleResult<Self> {
        let tag = tag.into();
        if !tag.starts_with("tag:") {
            return Err(TailscaleError::InvalidTag(format!(
                "tag must start with 'tag:': {tag}"
            )));
        }
        Ok(Self(tag))
    }

    /// Create a new FCP tag for a zone suffix.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fcp_tailscale::TailscaleTag;
    ///
    /// let tag = TailscaleTag::fcp_tag("work");
    /// assert_eq!(tag.as_str(), "tag:fcp-work");
    /// ```
    #[must_use]
    pub fn fcp_tag(suffix: &str) -> Self {
        Self(format!("{FCP_TAG_PREFIX}{suffix}"))
    }

    /// Get the tag as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this is an FCP tag (has `tag:fcp-` prefix).
    #[must_use]
    pub fn is_fcp_tag(&self) -> bool {
        self.0.starts_with(FCP_TAG_PREFIX)
    }

    /// Get the FCP zone suffix if this is an FCP tag.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fcp_tailscale::TailscaleTag;
    ///
    /// let tag = TailscaleTag::new("tag:fcp-work").unwrap();
    /// assert_eq!(tag.fcp_suffix(), Some("work"));
    ///
    /// let tag = TailscaleTag::new("tag:server").unwrap();
    /// assert_eq!(tag.fcp_suffix(), None);
    /// ```
    #[must_use]
    pub fn fcp_suffix(&self) -> Option<&str> {
        self.0.strip_prefix(FCP_TAG_PREFIX)
    }
}

impl std::fmt::Display for TailscaleTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Utilities for mapping between FCP zones and Tailscale tags.
///
/// # Zone ID Format
///
/// Zone IDs have the format `z:<name>` where `<name>` is a lowercase
/// alphanumeric string with optional hyphens.
///
/// # Example
///
/// ```rust
/// use fcp_tailscale::{ZoneTagMapping, TailscaleTag};
///
/// // Zone to tag
/// let tag = ZoneTagMapping::zone_to_tag("z:work").unwrap();
/// assert_eq!(tag.as_str(), "tag:fcp-work");
///
/// // Tag to zone
/// let tag = TailscaleTag::new("tag:fcp-private").unwrap();
/// let zone = ZoneTagMapping::tag_to_zone(&tag).unwrap();
/// assert_eq!(zone, "z:private");
/// ```
pub struct ZoneTagMapping;

impl ZoneTagMapping {
    /// Zone ID prefix (NORMATIVE).
    pub const ZONE_PREFIX: &'static str = "z:";

    /// Convert a zone ID to its Tailscale tag.
    ///
    /// # Errors
    ///
    /// Returns an error if the zone ID doesn't start with `z:`.
    pub fn zone_to_tag(zone_id: &str) -> TailscaleResult<TailscaleTag> {
        Self::try_zone_to_tag(zone_id)
    }

    /// Try to convert a zone ID to its Tailscale tag.
    ///
    /// # Errors
    ///
    /// Returns an error if the zone ID doesn't start with `z:`.
    pub fn try_zone_to_tag(zone_id: &str) -> TailscaleResult<TailscaleTag> {
        let suffix = zone_id
            .strip_prefix(Self::ZONE_PREFIX)
            .ok_or_else(|| TailscaleError::InvalidZoneId(zone_id.to_string()))?;
        Ok(TailscaleTag::fcp_tag(suffix))
    }

    /// Convert a Tailscale FCP tag to its zone ID.
    ///
    /// Returns `None` if the tag is not an FCP tag.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fcp_tailscale::{ZoneTagMapping, TailscaleTag};
    ///
    /// let tag = TailscaleTag::new("tag:fcp-community").unwrap();
    /// let zone = ZoneTagMapping::tag_to_zone(&tag).unwrap();
    /// assert_eq!(zone, "z:community");
    ///
    /// let tag = TailscaleTag::new("tag:server").unwrap();
    /// assert!(ZoneTagMapping::tag_to_zone(&tag).is_none());
    /// ```
    #[must_use]
    pub fn tag_to_zone(tag: &TailscaleTag) -> Option<String> {
        tag.fcp_suffix()
            .map(|suffix| format!("{}{suffix}", Self::ZONE_PREFIX))
    }

    /// Try to convert a Tailscale FCP tag to its zone ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the tag doesn't have the `tag:fcp-` prefix.
    pub fn try_tag_to_zone(tag: &TailscaleTag) -> TailscaleResult<String> {
        Self::tag_to_zone(tag).ok_or_else(|| TailscaleError::NotFcpTag(tag.to_string()))
    }

    /// Check if a zone ID is valid.
    ///
    /// Valid zone IDs:
    /// - Start with `z:`
    /// - Followed by 1+ lowercase alphanumeric characters or hyphens
    /// - Cannot start or end with a hyphen
    #[must_use]
    pub fn is_valid_zone_id(zone_id: &str) -> bool {
        let Some(suffix) = zone_id.strip_prefix(Self::ZONE_PREFIX) else {
            return false;
        };

        if suffix.is_empty() {
            return false;
        }

        if suffix.starts_with('-') || suffix.ends_with('-') {
            return false;
        }

        suffix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }

    /// Validate a zone ID and return it if valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the zone ID format is invalid.
    pub fn validate_zone_id(zone_id: &str) -> TailscaleResult<&str> {
        if Self::is_valid_zone_id(zone_id) {
            Ok(zone_id)
        } else {
            Err(TailscaleError::InvalidZoneId(zone_id.to_string()))
        }
    }

    /// Get all standard FCP zone IDs.
    #[must_use]
    pub const fn standard_zones() -> &'static [&'static str] {
        &["z:owner", "z:private", "z:work", "z:community", "z:public"]
    }
}

/// ACL rule generation for zone-based port gating.
///
/// This is a defense-in-depth feature that generates Tailscale ACL rules
/// to restrict network access based on zone membership.
#[derive(Debug, Clone)]
pub struct ZoneAclGenerator {
    /// Symbol port for zone traffic.
    pub symbol_port: u16,
    /// Control port for zone traffic.
    pub control_port: u16,
}

impl Default for ZoneAclGenerator {
    fn default() -> Self {
        Self {
            symbol_port: 4200,
            control_port: 4201,
        }
    }
}

impl ZoneAclGenerator {
    /// Create a new ACL generator with custom ports.
    #[must_use]
    pub const fn new(symbol_port: u16, control_port: u16) -> Self {
        Self {
            symbol_port,
            control_port,
        }
    }

    /// Generate an ACL rule allowing zone members to access zone ports.
    ///
    /// Returns a JSON-compatible ACL rule structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the zone ID is invalid.
    pub fn zone_access_rule(&self, zone_id: &str) -> TailscaleResult<ZoneAclRule> {
        let tag = ZoneTagMapping::zone_to_tag(zone_id)?;
        Ok(ZoneAclRule {
            action: "accept".to_string(),
            src: vec![tag.to_string()],
            dst: vec![
                format!("{}:{}", tag, self.symbol_port),
                format!("{}:{}", tag, self.control_port),
            ],
        })
    }

    /// Generate ACL rules for all standard zones.
    ///
    /// # Errors
    ///
    /// Returns an error if any standard zone ID is invalid.
    pub fn all_zone_rules(&self) -> TailscaleResult<Vec<ZoneAclRule>> {
        ZoneTagMapping::standard_zones()
            .iter()
            .map(|zone| self.zone_access_rule(zone))
            .collect()
    }
}

/// A Tailscale ACL rule for zone access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneAclRule {
    /// Action (always "accept" for zone rules).
    pub action: String,
    /// Source tags.
    pub src: Vec<String>,
    /// Destination tags with ports.
    pub dst: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tailscale_tag_new() {
        let tag = TailscaleTag::new("tag:server").unwrap();
        assert_eq!(tag.as_str(), "tag:server");

        // Invalid tag (no prefix)
        let result = TailscaleTag::new("server");
        assert!(result.is_err());
    }

    #[test]
    fn test_tailscale_tag_fcp_tag() {
        let tag = TailscaleTag::fcp_tag("work");
        assert_eq!(tag.as_str(), "tag:fcp-work");
        assert!(tag.is_fcp_tag());
    }

    #[test]
    fn test_tailscale_tag_is_fcp_tag() {
        let fcp_tag = TailscaleTag::new("tag:fcp-work").unwrap();
        assert!(fcp_tag.is_fcp_tag());

        let other_tag = TailscaleTag::new("tag:server").unwrap();
        assert!(!other_tag.is_fcp_tag());
    }

    #[test]
    fn test_tailscale_tag_fcp_suffix() {
        let tag = TailscaleTag::new("tag:fcp-private").unwrap();
        assert_eq!(tag.fcp_suffix(), Some("private"));

        let tag = TailscaleTag::new("tag:server").unwrap();
        assert_eq!(tag.fcp_suffix(), None);
    }

    #[test]
    fn test_zone_to_tag() {
        let tag = ZoneTagMapping::zone_to_tag("z:work").unwrap();
        assert_eq!(tag.as_str(), "tag:fcp-work");

        let tag = ZoneTagMapping::zone_to_tag("z:owner").unwrap();
        assert_eq!(tag.as_str(), "tag:fcp-owner");
    }

    #[test]
    fn test_try_zone_to_tag() {
        let tag = ZoneTagMapping::try_zone_to_tag("z:community").unwrap();
        assert_eq!(tag.as_str(), "tag:fcp-community");

        // Invalid zone
        let result = ZoneTagMapping::try_zone_to_tag("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_to_zone() {
        let tag = TailscaleTag::new("tag:fcp-private").unwrap();
        let zone = ZoneTagMapping::tag_to_zone(&tag).unwrap();
        assert_eq!(zone, "z:private");

        // Non-FCP tag returns None
        let tag = TailscaleTag::new("tag:server").unwrap();
        assert!(ZoneTagMapping::tag_to_zone(&tag).is_none());
    }

    #[test]
    fn test_try_tag_to_zone() {
        let tag = TailscaleTag::new("tag:fcp-public").unwrap();
        let zone = ZoneTagMapping::try_tag_to_zone(&tag).unwrap();
        assert_eq!(zone, "z:public");

        // Non-FCP tag returns error
        let tag = TailscaleTag::new("tag:server").unwrap();
        let result = ZoneTagMapping::try_tag_to_zone(&tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_zone_id() {
        assert!(ZoneTagMapping::is_valid_zone_id("z:work"));
        assert!(ZoneTagMapping::is_valid_zone_id("z:my-zone"));
        assert!(ZoneTagMapping::is_valid_zone_id("z:zone123"));

        // Invalid cases
        assert!(!ZoneTagMapping::is_valid_zone_id("work")); // Missing prefix
        assert!(!ZoneTagMapping::is_valid_zone_id("z:")); // Empty suffix
        assert!(!ZoneTagMapping::is_valid_zone_id("z:-work")); // Starts with hyphen
        assert!(!ZoneTagMapping::is_valid_zone_id("z:work-")); // Ends with hyphen
        assert!(!ZoneTagMapping::is_valid_zone_id("z:Work")); // Uppercase
        assert!(!ZoneTagMapping::is_valid_zone_id("z:my_zone")); // Underscore
    }

    #[test]
    fn test_standard_zones() {
        let zones = ZoneTagMapping::standard_zones();
        assert_eq!(zones.len(), 5);
        assert!(zones.contains(&"z:owner"));
        assert!(zones.contains(&"z:private"));
        assert!(zones.contains(&"z:work"));
        assert!(zones.contains(&"z:community"));
        assert!(zones.contains(&"z:public"));
    }

    #[test]
    fn test_roundtrip_zone_tag() {
        for zone in ZoneTagMapping::standard_zones() {
            let tag = ZoneTagMapping::zone_to_tag(zone).unwrap();
            let recovered_zone = ZoneTagMapping::tag_to_zone(&tag).unwrap();
            assert_eq!(&recovered_zone, zone);
        }
    }

    #[test]
    fn test_zone_acl_generator() {
        let generator = ZoneAclGenerator::default();
        let rule = generator.zone_access_rule("z:work").unwrap();

        assert_eq!(rule.action, "accept");
        assert_eq!(rule.src, vec!["tag:fcp-work"]);
        assert!(rule.dst.contains(&"tag:fcp-work:4200".to_string()));
        assert!(rule.dst.contains(&"tag:fcp-work:4201".to_string()));
    }

    #[test]
    fn test_zone_acl_generator_custom_ports() {
        let generator = ZoneAclGenerator::new(8080, 8081);
        let rule = generator.zone_access_rule("z:private").unwrap();

        assert!(rule.dst.contains(&"tag:fcp-private:8080".to_string()));
        assert!(rule.dst.contains(&"tag:fcp-private:8081".to_string()));
    }

    #[test]
    fn test_all_zone_rules() {
        let generator = ZoneAclGenerator::default();
        let rules = generator.all_zone_rules().unwrap();

        assert_eq!(rules.len(), 5);
    }
}
