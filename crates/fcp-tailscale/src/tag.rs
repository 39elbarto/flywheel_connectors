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
    /// Returns an error if the zone ID format is invalid.
    pub fn zone_to_tag(zone_id: &str) -> TailscaleResult<TailscaleTag> {
        Self::try_zone_to_tag(zone_id)
    }

    /// Try to convert a zone ID to its Tailscale tag.
    ///
    /// # Errors
    ///
    /// Returns an error if the zone ID format is invalid.
    pub fn try_zone_to_tag(zone_id: &str) -> TailscaleResult<TailscaleTag> {
        let zone_id = Self::validate_zone_id(zone_id)?;
        let suffix = zone_id
            .strip_prefix(Self::ZONE_PREFIX)
            .ok_or_else(|| TailscaleError::InvalidZoneId(zone_id.to_string()))?;
        Ok(TailscaleTag::fcp_tag(suffix))
    }

    /// Convert a Tailscale FCP tag to its zone ID.
    ///
    /// Returns `None` if the tag is not an FCP tag or does not encode a valid zone ID.
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
        let suffix = tag.fcp_suffix()?;
        let zone = format!("{}{suffix}", Self::ZONE_PREFIX);
        Self::is_valid_zone_id(&zone).then_some(zone)
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

    #[test]
    fn test_tag_display_matches_as_str() {
        let tag = TailscaleTag::new("tag:fcp-work").unwrap();
        assert_eq!(tag.to_string(), tag.as_str());
        assert_eq!(tag.to_string(), "tag:fcp-work");
    }

    #[test]
    fn test_tag_new_rejects_empty_string() {
        let result = TailscaleTag::new("");
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_new_accepts_tag_prefix_only() {
        // "tag:" with nothing after is technically valid per the constructor
        let tag = TailscaleTag::new("tag:").unwrap();
        assert_eq!(tag.as_str(), "tag:");
        assert!(!tag.is_fcp_tag());
    }

    #[test]
    fn test_tag_fcp_suffix_empty_suffix() {
        // "tag:fcp-" has an empty suffix
        let tag = TailscaleTag::new("tag:fcp-").unwrap();
        assert!(tag.is_fcp_tag());
        assert_eq!(tag.fcp_suffix(), Some(""));
    }

    #[test]
    fn test_validate_zone_id_returns_ok_for_valid() {
        let result = ZoneTagMapping::validate_zone_id("z:work");
        assert_eq!(result.unwrap(), "z:work");
    }

    #[test]
    fn test_validate_zone_id_returns_err_for_invalid() {
        let result = ZoneTagMapping::validate_zone_id("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_zone_acl_rule_serde_roundtrip() {
        let generator = ZoneAclGenerator::default();
        let rule = generator.zone_access_rule("z:work").unwrap();
        let json = serde_json::to_string(&rule).unwrap();
        let decoded: ZoneAclRule = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.action, rule.action);
        assert_eq!(decoded.src, rule.src);
        assert_eq!(decoded.dst, rule.dst);
    }

    #[test]
    fn test_zone_acl_rule_invalid_zone() {
        let generator = ZoneAclGenerator::default();
        let result = generator.zone_access_rule("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_all_standard_zones_are_valid() {
        for zone in ZoneTagMapping::standard_zones() {
            assert!(
                ZoneTagMapping::is_valid_zone_id(zone),
                "standard zone {zone} should be valid"
            );
        }
    }

    #[test]
    fn test_zone_default_ports() {
        let generator = ZoneAclGenerator::default();
        assert_eq!(generator.symbol_port, 4200);
        assert_eq!(generator.control_port, 4201);
    }

    #[test]
    fn test_tag_clone_and_eq() {
        let tag = TailscaleTag::new("tag:fcp-work").unwrap();
        let cloned = tag.clone();
        assert_eq!(tag, cloned);
    }

    #[test]
    fn test_tag_hash_consistent() {
        use std::collections::HashSet;
        let tag1 = TailscaleTag::new("tag:fcp-work").unwrap();
        let tag2 = TailscaleTag::new("tag:fcp-work").unwrap();
        let mut set = HashSet::new();
        set.insert(tag1);
        set.insert(tag2);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_is_valid_zone_id_with_digits() {
        assert!(ZoneTagMapping::is_valid_zone_id("z:zone1"));
        assert!(ZoneTagMapping::is_valid_zone_id("z:1zone"));
        assert!(ZoneTagMapping::is_valid_zone_id("z:123"));
    }

    #[test]
    fn test_is_valid_zone_id_consecutive_hyphens() {
        // Current implementation allows consecutive hyphens
        assert!(ZoneTagMapping::is_valid_zone_id("z:my--zone"));
    }

    // --- TailscaleTag serde roundtrip ---

    #[test]
    fn test_tag_serde_roundtrip_fcp() {
        let tag = TailscaleTag::fcp_tag("work");
        let json = serde_json::to_string(&tag).unwrap();
        let decoded: TailscaleTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, decoded);
        assert_eq!(decoded.as_str(), "tag:fcp-work");
    }

    #[test]
    fn test_tag_serde_roundtrip_non_fcp() {
        let tag = TailscaleTag::new("tag:server").unwrap();
        let json = serde_json::to_string(&tag).unwrap();
        let decoded: TailscaleTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, decoded);
    }

    // --- TailscaleTag Debug format ---

    #[test]
    fn test_tag_debug() {
        let tag = TailscaleTag::fcp_tag("private");
        let dbg = format!("{tag:?}");
        assert!(dbg.contains("TailscaleTag"));
        assert!(dbg.contains("tag:fcp-private"));
    }

    // --- ZoneTagMapping::validate_zone_id edge cases ---

    #[test]
    fn test_validate_zone_id_dot_rejected() {
        // Dots are not allowed in zone IDs
        let result = ZoneTagMapping::validate_zone_id("z:my.zone");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_zone_id_space_rejected() {
        let result = ZoneTagMapping::validate_zone_id("z:my zone");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_zone_id_unicode_rejected() {
        let result = ZoneTagMapping::validate_zone_id("z:zöne");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_zone_id_single_char() {
        // "z:a" — single char suffix is valid
        let result = ZoneTagMapping::validate_zone_id("z:a");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "z:a");
    }

    #[test]
    fn test_validate_zone_id_multi_hyphen() {
        // "z:a-b-c" — multi-hyphen is valid
        let result = ZoneTagMapping::validate_zone_id("z:a-b-c");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "z:a-b-c");
    }

    // --- ZoneAclGenerator: Clone, Debug, zero ports, max u16 ports ---

    #[test]
    fn test_zone_acl_generator_clone() {
        let acl_gen = ZoneAclGenerator::new(1000, 2000);
        #[allow(clippy::redundant_clone)]
        let cloned = acl_gen.clone();
        assert_eq!(cloned.symbol_port, 1000);
        assert_eq!(cloned.control_port, 2000);
    }

    #[test]
    fn test_zone_acl_generator_debug() {
        let acl_gen = ZoneAclGenerator::default();
        let dbg = format!("{acl_gen:?}");
        assert!(dbg.contains("ZoneAclGenerator"));
        assert!(dbg.contains("4200"));
        assert!(dbg.contains("4201"));
    }

    #[test]
    fn test_zone_acl_generator_zero_ports() {
        let acl_gen = ZoneAclGenerator::new(0, 0);
        let rule = acl_gen.zone_access_rule("z:work").unwrap();
        assert!(rule.dst.contains(&"tag:fcp-work:0".to_string()));
    }

    #[test]
    fn test_zone_acl_generator_max_ports() {
        let acl_gen = ZoneAclGenerator::new(u16::MAX, u16::MAX);
        let rule = acl_gen.zone_access_rule("z:owner").unwrap();
        assert!(rule.dst.contains(&format!("tag:fcp-owner:{}", u16::MAX)));
    }

    // --- ZoneAclRule: Clone, Debug, deserialize from JSON ---

    #[test]
    fn test_zone_acl_rule_clone() {
        let acl_gen = ZoneAclGenerator::default();
        let rule = acl_gen.zone_access_rule("z:work").unwrap();
        let cloned = rule.clone();
        assert_eq!(cloned.action, rule.action);
        assert_eq!(cloned.src, rule.src);
        assert_eq!(cloned.dst, rule.dst);
    }

    #[test]
    fn test_zone_acl_rule_debug() {
        let acl_gen = ZoneAclGenerator::default();
        let rule = acl_gen.zone_access_rule("z:public").unwrap();
        let dbg = format!("{rule:?}");
        assert!(dbg.contains("ZoneAclRule"));
        assert!(dbg.contains("accept"));
    }

    #[test]
    fn test_zone_acl_rule_deserialize_from_json_string() {
        let json = r#"{
            "action": "accept",
            "src": ["tag:fcp-work"],
            "dst": ["tag:fcp-work:4200"]
        }"#;
        let rule: ZoneAclRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.action, "accept");
        assert_eq!(rule.src, vec!["tag:fcp-work"]);
        assert_eq!(rule.dst, vec!["tag:fcp-work:4200"]);
    }

    // --- Tag Display matches as_str for non-FCP tags too ---

    #[test]
    fn test_tag_display_matches_as_str_non_fcp() {
        let tag = TailscaleTag::new("tag:my-server").unwrap();
        assert_eq!(tag.to_string(), tag.as_str());
        assert_eq!(tag.to_string(), "tag:my-server");
    }

    // --- Tag in sorted collection (BTreeSet) ---

    #[test]
    fn test_tag_in_btreeset() {
        use std::collections::BTreeSet;
        // TailscaleTag derives Eq + Hash but needs Ord for BTreeSet;
        // if Ord is not derived, we collect into a sorted Vec instead.
        let mut tags = vec![
            TailscaleTag::fcp_tag("work"),
            TailscaleTag::fcp_tag("owner"),
            TailscaleTag::fcp_tag("public"),
            TailscaleTag::fcp_tag("work"), // duplicate
        ];
        tags.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        tags.dedup();
        assert_eq!(tags.len(), 3);
        // Verify sorted order
        assert_eq!(tags[0].as_str(), "tag:fcp-owner");
        assert_eq!(tags[1].as_str(), "tag:fcp-public");
        assert_eq!(tags[2].as_str(), "tag:fcp-work");

        // Also verify BTreeSet via string keys
        let set: BTreeSet<String> = tags.iter().map(|t| t.as_str().to_string()).collect();
        assert_eq!(set.len(), 3);
    }

    // --- TailscaleTag: Display for non-fcp and fcp ---

    #[test]
    fn test_tag_display_non_fcp() {
        let tag = TailscaleTag::new("tag:webserver").unwrap();
        assert_eq!(format!("{tag}"), "tag:webserver");
    }

    #[test]
    fn test_tag_display_fcp_community() {
        let tag = TailscaleTag::fcp_tag("community");
        assert_eq!(format!("{tag}"), "tag:fcp-community");
    }

    // --- TailscaleTag new: rejects various invalid prefixes ---

    #[test]
    fn test_tag_new_rejects_plain_word() {
        assert!(TailscaleTag::new("hello").is_err());
    }

    #[test]
    fn test_tag_new_rejects_partial_prefix() {
        assert!(TailscaleTag::new("ta:foo").is_err());
    }

    #[test]
    fn test_tag_new_rejects_uppercase_tag() {
        assert!(TailscaleTag::new("TAG:server").is_err());
    }

    #[test]
    fn test_tag_new_rejects_colon_only() {
        assert!(TailscaleTag::new(":").is_err());
    }

    #[test]
    fn test_tag_new_accepts_tag_with_special_chars() {
        // tag: prefix is satisfied; the rest can be anything per the constructor
        let tag = TailscaleTag::new("tag:special_chars-123!").unwrap();
        assert_eq!(tag.as_str(), "tag:special_chars-123!");
    }

    // --- TailscaleTag fcp_tag with various suffixes ---

    #[test]
    fn test_fcp_tag_empty_suffix() {
        let tag = TailscaleTag::fcp_tag("");
        assert_eq!(tag.as_str(), "tag:fcp-");
        assert!(tag.is_fcp_tag());
        assert_eq!(tag.fcp_suffix(), Some(""));
    }

    #[test]
    fn test_fcp_tag_long_suffix() {
        let long_suffix = "a".repeat(256);
        let tag = TailscaleTag::fcp_tag(&long_suffix);
        assert!(tag.is_fcp_tag());
        assert_eq!(tag.fcp_suffix(), Some(long_suffix.as_str()));
    }

    #[test]
    fn test_fcp_tag_numeric_suffix() {
        let tag = TailscaleTag::fcp_tag("12345");
        assert_eq!(tag.as_str(), "tag:fcp-12345");
        assert!(tag.is_fcp_tag());
    }

    // --- TailscaleTag: serde with unicode ---

    #[test]
    fn test_tag_serde_roundtrip_unicode() {
        let tag = TailscaleTag::new("tag:café").unwrap();
        let json = serde_json::to_string(&tag).unwrap();
        let decoded: TailscaleTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, decoded);
    }

    // --- TailscaleTag equality and inequality ---

    #[test]
    fn test_tag_not_equal_different_tags() {
        let tag1 = TailscaleTag::fcp_tag("work");
        let tag2 = TailscaleTag::fcp_tag("private");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_tag_equal_same_tag() {
        let tag1 = TailscaleTag::new("tag:fcp-work").unwrap();
        let tag2 = TailscaleTag::fcp_tag("work");
        assert_eq!(tag1, tag2);
    }

    // --- ZoneTagMapping: zone_to_tag edge cases ---

    #[test]
    fn test_zone_to_tag_empty_suffix() {
        let result = ZoneTagMapping::zone_to_tag("z:");
        assert!(result.is_err());
    }

    #[test]
    fn test_zone_to_tag_rejects_no_prefix() {
        assert!(ZoneTagMapping::zone_to_tag("work").is_err());
    }

    #[test]
    fn test_zone_to_tag_rejects_empty_string() {
        assert!(ZoneTagMapping::zone_to_tag("").is_err());
    }

    #[test]
    fn test_zone_to_tag_with_uppercase_suffix() {
        let result = ZoneTagMapping::zone_to_tag("z:UPPER");
        assert!(result.is_err());
    }

    // --- ZoneTagMapping: tag_to_zone edge cases ---

    #[test]
    fn test_tag_to_zone_with_empty_fcp_suffix() {
        let tag = TailscaleTag::new("tag:fcp-").unwrap();
        let zone = ZoneTagMapping::tag_to_zone(&tag);
        assert!(zone.is_none());
    }

    #[test]
    fn test_tag_to_zone_with_hyphenated_suffix() {
        let tag = TailscaleTag::fcp_tag("my-custom-zone");
        let zone = ZoneTagMapping::tag_to_zone(&tag).unwrap();
        assert_eq!(zone, "z:my-custom-zone");
    }

    // --- ZoneTagMapping: try_tag_to_zone error contains tag name ---

    #[test]
    fn test_try_tag_to_zone_error_contains_tag() {
        let tag = TailscaleTag::new("tag:server").unwrap();
        let err = ZoneTagMapping::try_tag_to_zone(&tag).unwrap_err();
        assert!(err.to_string().contains("tag:server"));
    }

    // --- ZoneTagMapping: is_valid_zone_id more edge cases ---

    #[test]
    fn test_valid_zone_id_single_digit() {
        assert!(ZoneTagMapping::is_valid_zone_id("z:0"));
    }

    #[test]
    fn test_valid_zone_id_all_digits() {
        assert!(ZoneTagMapping::is_valid_zone_id("z:9876543210"));
    }

    #[test]
    fn test_invalid_zone_id_hyphen_only() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z:-"));
    }

    #[test]
    fn test_invalid_zone_id_double_colon() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z::work"));
    }

    #[test]
    fn test_invalid_zone_id_with_at_sign() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z:user@zone"));
    }

    #[test]
    fn test_invalid_zone_id_with_slash() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z:my/zone"));
    }

    // --- ZoneTagMapping: standard zones roundtrip fully ---

    #[test]
    fn test_standard_zones_all_valid_and_roundtrippable() {
        for zone in ZoneTagMapping::standard_zones() {
            assert!(ZoneTagMapping::is_valid_zone_id(zone));
            let tag = ZoneTagMapping::zone_to_tag(zone).unwrap();
            assert!(tag.is_fcp_tag());
            let recovered = ZoneTagMapping::tag_to_zone(&tag).unwrap();
            assert_eq!(&recovered, zone);
            let validated = ZoneTagMapping::validate_zone_id(zone).unwrap();
            assert_eq!(validated, *zone);
        }
    }

    // --- ZoneAclGenerator: all_zone_rules produces correct structure ---

    #[test]
    fn test_all_zone_rules_structure() {
        let acl = ZoneAclGenerator::new(5000, 5001);
        let rules = acl.all_zone_rules().unwrap();
        assert_eq!(rules.len(), 5);
        for rule in &rules {
            assert_eq!(rule.action, "accept");
            assert_eq!(rule.src.len(), 1);
            assert_eq!(rule.dst.len(), 2);
            // Each dst should contain ":5000" or ":5001"
            assert!(rule.dst[0].contains(":5000"));
            assert!(rule.dst[1].contains(":5001"));
        }
    }

    // --- ZoneAclRule serde with custom action ---

    #[test]
    fn test_zone_acl_rule_from_json_custom_fields() {
        let json = r#"{
            "action": "deny",
            "src": ["tag:fcp-owner", "tag:fcp-private"],
            "dst": ["tag:fcp-work:8080", "tag:fcp-work:8443"]
        }"#;
        let rule: ZoneAclRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.action, "deny");
        assert_eq!(rule.src.len(), 2);
        assert_eq!(rule.dst.len(), 2);
    }

    // --- ZoneAclRule: empty src/dst ---

    #[test]
    fn test_zone_acl_rule_empty_src_dst() {
        let rule = ZoneAclRule {
            action: "accept".to_string(),
            src: vec![],
            dst: vec![],
        };
        let json = serde_json::to_string(&rule).unwrap();
        let decoded: ZoneAclRule = serde_json::from_str(&json).unwrap();
        assert!(decoded.src.is_empty());
        assert!(decoded.dst.is_empty());
    }

    // --- ZoneAclGenerator with port 1 ---

    #[test]
    fn test_zone_acl_generator_port_one() {
        let acl3 = ZoneAclGenerator::new(1, 1);
        let rule = acl3.zone_access_rule("z:work").unwrap();
        assert!(rule.dst.contains(&"tag:fcp-work:1".to_string()));
    }

    // --- ZoneAclGenerator: same port for symbol and control ---

    #[test]
    fn test_zone_acl_generator_same_ports() {
        let acl2 = ZoneAclGenerator::new(9999, 9999);
        let rule = acl2.zone_access_rule("z:owner").unwrap();
        assert_eq!(rule.dst.len(), 2);
        assert_eq!(rule.dst[0], "tag:fcp-owner:9999");
        assert_eq!(rule.dst[1], "tag:fcp-owner:9999");
    }

    // --- ZONE_PREFIX constant ---

    #[test]
    fn test_zone_prefix_constant() {
        assert_eq!(ZoneTagMapping::ZONE_PREFIX, "z:");
    }

    // --- FCP_TAG_PREFIX from crate root ---

    #[test]
    fn test_fcp_tag_prefix_constant() {
        assert_eq!(crate::FCP_TAG_PREFIX, "tag:fcp-");
    }

    // --- TailscaleTag: Hash with different tags in HashSet ---

    #[test]
    fn test_tag_hash_different_tags() {
        use std::collections::HashSet;
        let tag1 = TailscaleTag::fcp_tag("owner");
        let tag2 = TailscaleTag::fcp_tag("private");
        let tag3 = TailscaleTag::new("tag:server").unwrap();
        let mut set = HashSet::new();
        set.insert(tag1);
        set.insert(tag2);
        set.insert(tag3);
        assert_eq!(set.len(), 3);
    }

    // --- TailscaleTag: serde JSON value shape ---

    #[test]
    fn test_tag_serde_json_is_string() {
        let tag = TailscaleTag::fcp_tag("owner");
        let val: serde_json::Value = serde_json::to_value(&tag).unwrap();
        assert!(val.is_string());
        assert_eq!(val.as_str().unwrap(), "tag:fcp-owner");
    }

    #[test]
    fn test_tag_deserialize_from_string_value() {
        let val = serde_json::Value::String("tag:fcp-public".to_string());
        let tag: TailscaleTag = serde_json::from_value(val).unwrap();
        assert_eq!(tag.as_str(), "tag:fcp-public");
    }

    // --- TailscaleTag: is_fcp_tag boundary ---

    #[test]
    fn test_tag_fcp_prefix_partial_not_fcp() {
        // "tag:fcp" without trailing hyphen is NOT an fcp tag
        let tag = TailscaleTag::new("tag:fcp").unwrap();
        assert!(!tag.is_fcp_tag());
        assert!(tag.fcp_suffix().is_none());
    }

    #[test]
    fn test_tag_fcp_prefix_case_sensitivity() {
        let tag = TailscaleTag::new("tag:FCP-work").unwrap();
        assert!(!tag.is_fcp_tag());
    }

    // --- ZoneTagMapping: validate_zone_id with tab/newline ---

    #[test]
    fn test_invalid_zone_id_with_tab() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z:my\tzone"));
    }

    #[test]
    fn test_invalid_zone_id_with_newline() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z:my\nzone"));
    }

    #[test]
    fn test_invalid_zone_id_with_hash() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z:zone#1"));
    }

    #[test]
    fn test_invalid_zone_id_with_plus() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z:zone+1"));
    }

    // --- ZoneTagMapping: validate_zone_id returns borrowed str on success ---

    #[test]
    fn test_validate_zone_id_returns_same_reference() {
        let zone_id = "z:my-zone";
        let result = ZoneTagMapping::validate_zone_id(zone_id).unwrap();
        assert!(std::ptr::eq(result, zone_id));
    }

    // --- ZoneTagMapping: roundtrip with all standard zones via try_ variants ---

    #[test]
    fn test_standard_zones_roundtrip_via_try_variants() {
        for zone in ZoneTagMapping::standard_zones() {
            let tag = ZoneTagMapping::try_zone_to_tag(zone).unwrap();
            let recovered = ZoneTagMapping::try_tag_to_zone(&tag).unwrap();
            assert_eq!(&recovered, zone);
        }
    }

    // --- ZoneAclGenerator: rule src always has exactly one entry ---

    #[test]
    fn test_zone_acl_rule_src_always_single() {
        let acl_gen = ZoneAclGenerator::default();
        for zone in ZoneTagMapping::standard_zones() {
            let rule = acl_gen.zone_access_rule(zone).unwrap();
            assert_eq!(rule.src.len(), 1);
        }
    }

    // --- ZoneAclGenerator: dst entries have correct format ---

    #[test]
    fn test_zone_acl_rule_dst_format() {
        let acl_gen = ZoneAclGenerator::new(3000, 3001);
        let rule = acl_gen.zone_access_rule("z:community").unwrap();
        assert_eq!(rule.dst[0], "tag:fcp-community:3000");
        assert_eq!(rule.dst[1], "tag:fcp-community:3001");
    }

    // --- ZoneAclRule: serde roundtrip preserves all fields ---

    #[test]
    fn test_zone_acl_rule_serde_roundtrip_full() {
        let rule = ZoneAclRule {
            action: "accept".to_string(),
            src: vec!["tag:fcp-work".to_string(), "tag:fcp-owner".to_string()],
            dst: vec![
                "tag:fcp-work:4200".to_string(),
                "tag:fcp-work:4201".to_string(),
                "tag:fcp-owner:4200".to_string(),
            ],
        };
        let json = serde_json::to_string(&rule).unwrap();
        let decoded: ZoneAclRule = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.action, "accept");
        assert_eq!(decoded.src.len(), 2);
        assert_eq!(decoded.dst.len(), 3);
    }

    // --- ZoneAclRule: JSON field names ---

    #[test]
    fn test_zone_acl_rule_json_field_names() {
        let acl_gen = ZoneAclGenerator::default();
        let rule = acl_gen.zone_access_rule("z:work").unwrap();
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"action\""));
        assert!(json.contains("\"src\""));
        assert!(json.contains("\"dst\""));
    }

    // --- ZoneAclGenerator: all_zone_rules order matches standard_zones ---

    #[test]
    fn test_all_zone_rules_order() {
        let acl_gen = ZoneAclGenerator::default();
        let rules = acl_gen.all_zone_rules().unwrap();
        let zones = ZoneTagMapping::standard_zones();
        assert_eq!(rules.len(), zones.len());
        for (rule, zone) in rules.iter().zip(zones.iter()) {
            let expected_tag = ZoneTagMapping::zone_to_tag(zone).unwrap();
            assert_eq!(rule.src[0], expected_tag.to_string());
        }
    }

    // --- TailscaleTag: from_str-like construction ---

    #[test]
    fn test_tag_new_from_string_ref() {
        let s = String::from("tag:dynamic");
        let tag = TailscaleTag::new(&s).unwrap();
        assert_eq!(tag.as_str(), "tag:dynamic");
    }

    #[test]
    fn test_tag_new_from_owned_string() {
        let tag = TailscaleTag::new(String::from("tag:owned")).unwrap();
        assert_eq!(tag.as_str(), "tag:owned");
    }

    // --- TailscaleTag: Display format for fcp_tag with hyphenated suffix ---

    #[test]
    fn test_tag_display_hyphenated_suffix() {
        let tag = TailscaleTag::fcp_tag("my-custom-zone");
        assert_eq!(format!("{tag}"), "tag:fcp-my-custom-zone");
    }

    // --- ZoneTagMapping: zone_to_tag with special characters in suffix ---

    #[test]
    fn test_zone_to_tag_with_special_chars() {
        // zone_to_tag only validates prefix, not suffix content
        let tag = ZoneTagMapping::zone_to_tag("z:123-abc").unwrap();
        assert_eq!(tag.as_str(), "tag:fcp-123-abc");
    }

    // --- ZoneTagMapping: is_valid_zone_id with numeric-only ---

    #[test]
    fn test_valid_zone_id_long_numeric() {
        assert!(ZoneTagMapping::is_valid_zone_id("z:00000000"));
    }

    #[test]
    fn test_valid_zone_id_mixed_alpha_digit_hyphen() {
        assert!(ZoneTagMapping::is_valid_zone_id("z:a1-b2-c3"));
    }

    // --- ZoneAclGenerator: const constructor ---

    #[test]
    fn test_zone_acl_generator_const_new() {
        const GEN: ZoneAclGenerator = ZoneAclGenerator::new(7000, 7001);
        assert_eq!(GEN.symbol_port, 7000);
        assert_eq!(GEN.control_port, 7001);
    }

    // --- TailscaleTag: fcp_tag with digits and hyphens ---

    #[test]
    fn test_fcp_tag_digit_hyphen_suffix() {
        let tag = TailscaleTag::fcp_tag("zone-42-beta");
        assert_eq!(tag.as_str(), "tag:fcp-zone-42-beta");
        assert!(tag.is_fcp_tag());
        assert_eq!(tag.fcp_suffix(), Some("zone-42-beta"));
    }

    // --- ZoneTagMapping: try_tag_to_zone error type ---

    #[test]
    fn test_try_tag_to_zone_error_is_not_fcp_tag() {
        let tag = TailscaleTag::new("tag:infra").unwrap();
        let err = ZoneTagMapping::try_tag_to_zone(&tag).unwrap_err();
        let debug = format!("{err:?}");
        assert!(debug.contains("NotFcpTag"));
    }

    // --- ZoneTagMapping: try_zone_to_tag error type ---

    #[test]
    fn test_try_zone_to_tag_error_is_invalid_zone_id() {
        let err = ZoneTagMapping::try_zone_to_tag("badzone").unwrap_err();
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidZoneId"));
    }

    // --- Tag: serde deserialization from invalid JSON ---

    #[test]
    fn test_tag_deserialize_from_number_fails() {
        let result: Result<TailscaleTag, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_deserialize_from_null_fails() {
        let result: Result<TailscaleTag, _> = serde_json::from_str("null");
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_deserialize_from_bool_fails() {
        let result: Result<TailscaleTag, _> = serde_json::from_str("true");
        assert!(result.is_err());
    }

    // --- Tag: new with whitespace ---

    #[test]
    fn test_tag_new_with_leading_whitespace() {
        assert!(TailscaleTag::new(" tag:server").is_err());
    }

    #[test]
    fn test_tag_new_with_trailing_whitespace() {
        // "tag: server" starts with "tag:" so it's accepted
        let tag = TailscaleTag::new("tag: server").unwrap();
        assert_eq!(tag.as_str(), "tag: server");
    }

    // --- Tag: Display idempotency ---

    #[test]
    fn test_tag_display_idempotent() {
        let tag = TailscaleTag::fcp_tag("zone");
        let d1 = tag.to_string();
        let d2 = tag.to_string();
        assert_eq!(d1, d2);
    }

    // --- Tag: is_fcp_tag boundary with similar prefixes ---

    #[test]
    fn test_tag_fcp_dash_prefix_required() {
        let tag = TailscaleTag::new("tag:fcpx").unwrap();
        assert!(!tag.is_fcp_tag());
        assert!(tag.fcp_suffix().is_none());
    }

    #[test]
    fn test_tag_fcp_double_dash() {
        let tag = TailscaleTag::new("tag:fcp--work").unwrap();
        assert!(tag.is_fcp_tag());
        assert_eq!(tag.fcp_suffix(), Some("-work"));
    }

    // --- ZoneAclRule: serde roundtrip with empty action ---

    #[test]
    fn test_zone_acl_rule_serde_empty_action() {
        let rule = ZoneAclRule {
            action: String::new(),
            src: vec!["tag:fcp-work".to_string()],
            dst: vec!["tag:fcp-work:4200".to_string()],
        };
        let json = serde_json::to_string(&rule).unwrap();
        let decoded: ZoneAclRule = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.action, "");
    }

    // --- ZoneTagMapping: validate_zone_id with emoji ---

    #[test]
    fn test_validate_zone_id_emoji_rejected() {
        let result = ZoneTagMapping::validate_zone_id("z:zone\u{1F600}");
        assert!(result.is_err());
    }

    // --- Tag: serde roundtrip in a vec ---

    #[test]
    fn test_tags_vec_serde_roundtrip() {
        let tags = vec![
            TailscaleTag::fcp_tag("owner"),
            TailscaleTag::fcp_tag("work"),
            TailscaleTag::new("tag:infra").unwrap(),
        ];
        let json = serde_json::to_string(&tags).unwrap();
        let decoded: Vec<TailscaleTag> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], tags[0]);
        assert_eq!(decoded[1], tags[1]);
        assert_eq!(decoded[2], tags[2]);
    }

    // --- ZoneAclGenerator: all_zone_rules with max ports ---

    #[test]
    fn test_all_zone_rules_max_ports() {
        let acl_gen = ZoneAclGenerator::new(u16::MAX, u16::MAX);
        let rules = acl_gen.all_zone_rules().unwrap();
        assert_eq!(rules.len(), 5);
        for rule in &rules {
            for dst in &rule.dst {
                assert!(dst.ends_with(&format!(":{}", u16::MAX)));
            }
        }
    }

    // --- ZoneTagMapping: zone_to_tag with unicode suffix ---

    #[test]
    fn test_zone_to_tag_unicode_suffix() {
        let result = ZoneTagMapping::zone_to_tag("z:\u{00e9}");
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_to_zone_rejects_invalid_fcp_suffix() {
        let tag = TailscaleTag::new("tag:fcp--work").unwrap();
        let zone = ZoneTagMapping::tag_to_zone(&tag);
        assert!(zone.is_none());
    }

    // --- ZoneAclGenerator: rules for each individual standard zone ---

    #[test]
    fn test_zone_acl_rule_owner() {
        let acl_gen = ZoneAclGenerator::default();
        let rule = acl_gen.zone_access_rule("z:owner").unwrap();
        assert_eq!(rule.src[0], "tag:fcp-owner");
        assert_eq!(rule.dst[0], "tag:fcp-owner:4200");
        assert_eq!(rule.dst[1], "tag:fcp-owner:4201");
    }

    #[test]
    fn test_zone_acl_rule_community() {
        let acl_gen = ZoneAclGenerator::default();
        let rule = acl_gen.zone_access_rule("z:community").unwrap();
        assert_eq!(rule.src[0], "tag:fcp-community");
    }

    #[test]
    fn test_zone_acl_rule_public() {
        let acl_gen = ZoneAclGenerator::default();
        let rule = acl_gen.zone_access_rule("z:public").unwrap();
        assert_eq!(rule.src[0], "tag:fcp-public");
    }

    // --- ZoneTagMapping: validate_zone_id returns err message containing input ---

    #[test]
    fn test_validate_zone_id_error_contains_input() {
        let result = ZoneTagMapping::validate_zone_id("not-a-zone");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not-a-zone"));
    }

    // --- TailscaleTag: Hash uniqueness for different tags ---

    #[test]
    fn test_tag_hash_many_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for i in 0..25 {
            set.insert(TailscaleTag::fcp_tag(&format!("zone{i}")));
        }
        assert_eq!(set.len(), 25);
    }

    // --- ZoneAclRule: Debug output contains field values ---

    #[test]
    fn test_zone_acl_rule_debug_detailed() {
        let rule = ZoneAclRule {
            action: "accept".to_string(),
            src: vec!["tag:fcp-owner".to_string()],
            dst: vec!["tag:fcp-owner:9090".to_string()],
        };
        let dbg = format!("{rule:?}");
        assert!(dbg.contains("accept"));
        assert!(dbg.contains("tag:fcp-owner"));
        assert!(dbg.contains("9090"));
    }

    // --- ZoneAclGenerator: Debug shows port values ---

    #[test]
    fn test_zone_acl_generator_debug_custom_ports() {
        let acl_gen = ZoneAclGenerator::new(1234, 5678);
        let dbg = format!("{acl_gen:?}");
        assert!(dbg.contains("1234"));
        assert!(dbg.contains("5678"));
    }

    // --- ZoneTagMapping: is_valid_zone_id edge: only hyphens in middle ---

    #[test]
    fn test_valid_zone_id_hyphens_in_middle() {
        assert!(ZoneTagMapping::is_valid_zone_id("z:a-b"));
        assert!(ZoneTagMapping::is_valid_zone_id("z:1-2"));
    }

    #[test]
    fn test_invalid_zone_id_only_two_hyphens() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z:--"));
    }

    // --- ZoneTagMapping: try_zone_to_tag and zone_to_tag produce same result ---

    #[test]
    fn test_zone_to_tag_and_try_produce_same() {
        for zone in ZoneTagMapping::standard_zones() {
            let tag1 = ZoneTagMapping::zone_to_tag(zone).unwrap();
            let tag2 = ZoneTagMapping::try_zone_to_tag(zone).unwrap();
            assert_eq!(tag1, tag2);
        }
    }

    // --- ZoneAclRule: serde with large src/dst arrays ---

    #[test]
    fn test_zone_acl_rule_serde_large_arrays() {
        let rule = ZoneAclRule {
            action: "accept".to_string(),
            src: (0..50).map(|i| format!("tag:fcp-zone{i}")).collect(),
            dst: (0..100).map(|i| format!("tag:fcp-zone{i}:4200")).collect(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let decoded: ZoneAclRule = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.src.len(), 50);
        assert_eq!(decoded.dst.len(), 100);
    }

    // --- Tag: Display for tag:fcp- (bare prefix) ---

    #[test]
    fn test_tag_display_bare_fcp_prefix() {
        let tag = TailscaleTag::fcp_tag("");
        assert_eq!(format!("{tag}"), "tag:fcp-");
    }

    // --- ZoneTagMapping: is_valid_zone_id with percent encoding ---

    #[test]
    fn test_invalid_zone_id_percent_encoding() {
        assert!(!ZoneTagMapping::is_valid_zone_id("z:zone%20name"));
    }

    // --- ZoneAclGenerator: all_zone_rules serde roundtrip ---

    #[test]
    fn test_all_zone_rules_serde_roundtrip() {
        let acl_gen = ZoneAclGenerator::default();
        let rules = acl_gen.all_zone_rules().unwrap();
        let json = serde_json::to_string(&rules).unwrap();
        let decoded: Vec<ZoneAclRule> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.len(), 5);
        for (rule, decoded_rule) in rules.iter().zip(decoded.iter()) {
            assert_eq!(rule.action, decoded_rule.action);
            assert_eq!(rule.src, decoded_rule.src);
            assert_eq!(rule.dst, decoded_rule.dst);
        }
    }

    // --- Tag: new rejects tab character prefix ---

    #[test]
    fn test_tag_new_rejects_tab_prefix() {
        assert!(TailscaleTag::new("\ttag:server").is_err());
    }

    // --- ZoneTagMapping: standard_zones all start with z: ---

    #[test]
    fn test_standard_zones_all_start_with_z_prefix() {
        for zone in ZoneTagMapping::standard_zones() {
            assert!(
                zone.starts_with("z:"),
                "expected zone to start with 'z:', got: {zone}"
            );
        }
    }

    // --- Tag: serde roundtrip with hyphenated non-fcp tag ---

    #[test]
    fn test_tag_serde_roundtrip_hyphenated_non_fcp() {
        let tag = TailscaleTag::new("tag:my-custom-server-tag").unwrap();
        let json = serde_json::to_string(&tag).unwrap();
        let decoded: TailscaleTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, decoded);
        assert!(!decoded.is_fcp_tag());
    }

    // --- ZoneAclGenerator: zone_access_rule dst has exactly 2 entries ---

    #[test]
    fn test_zone_acl_rule_dst_always_two_entries() {
        let acl_gen = ZoneAclGenerator::new(80, 443);
        for zone in ZoneTagMapping::standard_zones() {
            let rule = acl_gen.zone_access_rule(zone).unwrap();
            assert_eq!(rule.dst.len(), 2, "expected 2 dst entries for zone {zone}");
        }
    }
}
