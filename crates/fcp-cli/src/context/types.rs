//! Context configuration types for multi-mesh management.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level context configuration file (stored at `~/.fcp/contexts.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextConfig {
    /// Currently active context name.
    pub current_context: String,
    /// Available contexts keyed by name.
    pub contexts: BTreeMap<String, MeshContext>,
}

impl Default for ContextConfig {
    fn default() -> Self {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "local".to_string(),
            MeshContext {
                name: "local".to_string(),
                endpoint: "unix:///tmp/fcp-dev.sock".to_string(),
                default_zone: Some("z:work".to_string()),
                node_identity: None,
                config_overrides: BTreeMap::new(),
            },
        );
        Self {
            current_context: "local".to_string(),
            contexts,
        }
    }
}

impl ContextConfig {
    /// Schema version for the config file.
    pub const SCHEMA_VERSION: &'static str = "1.0.0";

    /// Load configuration from the default path or create a default.
    pub fn load_or_default() -> anyhow::Result<Self> {
        let path = Self::config_path()?;
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let config: Self = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    /// Save configuration to the default path.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    /// Return the config file path (`~/.fcp/contexts.toml`).
    ///
    /// Respects `FCP_CONFIG_DIR` env var, falls back to `$HOME/.fcp`.
    pub fn config_path() -> anyhow::Result<PathBuf> {
        let dir = if let Ok(dir) = std::env::var("FCP_CONFIG_DIR") {
            PathBuf::from(dir)
        } else {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .map_err(|_| anyhow::anyhow!("cannot determine home directory"))?;
            PathBuf::from(home).join(".fcp")
        };
        Ok(dir.join("contexts.toml"))
    }
}

/// A single mesh context configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshContext {
    /// Context display name.
    pub name: String,
    /// Mesh endpoint (e.g., `unix:///var/run/fcp/node.sock`,
    /// `tcp://192.168.1.100:9000`).
    pub endpoint: String,
    /// Default zone for commands that accept `--zone`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_zone: Option<String>,
    /// Path to node identity key for this mesh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_identity: Option<PathBuf>,
    /// Additional context-specific config overrides.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config_overrides: BTreeMap<String, serde_json::Value>,
}

/// JSON-serializable context listing output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextListOutput {
    /// Schema version.
    pub schema_version: String,
    /// Currently active context name.
    pub current_context: String,
    /// All available contexts.
    pub contexts: Vec<ContextSummary>,
}

/// Summary of a single context for list output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSummary {
    /// Context name.
    pub name: String,
    /// Whether this is the active context.
    pub active: bool,
    /// Mesh endpoint.
    pub endpoint: String,
    /// Default zone if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_zone: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ContextConfig default ----

    #[test]
    fn context_config_default_has_local() {
        let config = ContextConfig::default();
        assert_eq!(config.current_context, "local");
        assert!(config.contexts.contains_key("local"));
    }

    #[test]
    fn context_config_default_local_endpoint() {
        let config = ContextConfig::default();
        let local = config.contexts.get("local").unwrap();
        assert_eq!(local.endpoint, "unix:///tmp/fcp-dev.sock");
        assert_eq!(local.default_zone.as_deref(), Some("z:work"));
    }

    #[test]
    fn context_config_schema_version() {
        assert_eq!(ContextConfig::SCHEMA_VERSION, "1.0.0");
    }

    // ---- ContextConfig serde ----

    #[test]
    fn context_config_json_roundtrip() {
        let config = ContextConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: ContextConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.current_context, "local");
        assert_eq!(back.contexts.len(), 1);
    }

    #[test]
    fn context_config_toml_roundtrip() {
        let config = ContextConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let back: ContextConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(back.current_context, "local");
    }

    // ---- MeshContext serde ----

    #[test]
    fn mesh_context_full_roundtrip() {
        let ctx = MeshContext {
            name: "prod".to_string(),
            endpoint: "tcp://10.0.0.1:9000".to_string(),
            default_zone: Some("z:production".to_string()),
            node_identity: Some(PathBuf::from("/keys/node.key")),
            config_overrides: BTreeMap::new(),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: MeshContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "prod");
        assert_eq!(back.endpoint, "tcp://10.0.0.1:9000");
        assert_eq!(back.default_zone.as_deref(), Some("z:production"));
    }

    #[test]
    fn mesh_context_minimal() {
        let json = r#"{"name":"test","endpoint":"unix:///tmp/test.sock"}"#;
        let ctx: MeshContext = serde_json::from_str(json).unwrap();
        assert_eq!(ctx.name, "test");
        assert!(ctx.default_zone.is_none());
        assert!(ctx.node_identity.is_none());
        assert!(ctx.config_overrides.is_empty());
    }

    #[test]
    fn mesh_context_with_overrides() {
        let mut overrides = BTreeMap::new();
        overrides.insert("timeout_ms".to_string(), serde_json::json!(5000));
        let ctx = MeshContext {
            name: "staging".to_string(),
            endpoint: "tcp://staging:9000".to_string(),
            default_zone: None,
            node_identity: None,
            config_overrides: overrides,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: MeshContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.config_overrides["timeout_ms"], 5000);
    }

    // ---- ContextListOutput serde ----

    #[test]
    fn context_list_output_roundtrip() {
        let output = ContextListOutput {
            schema_version: "1.0.0".to_string(),
            current_context: "local".to_string(),
            contexts: vec![
                ContextSummary {
                    name: "local".to_string(),
                    active: true,
                    endpoint: "unix:///tmp/fcp.sock".to_string(),
                    default_zone: Some("z:work".to_string()),
                },
                ContextSummary {
                    name: "prod".to_string(),
                    active: false,
                    endpoint: "tcp://prod:9000".to_string(),
                    default_zone: None,
                },
            ],
        };
        let json = serde_json::to_string(&output).unwrap();
        let back: ContextListOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.contexts.len(), 2);
        assert!(back.contexts[0].active);
        assert!(!back.contexts[1].active);
    }

    // ---- Debug ----

    #[test]
    fn context_config_debug() {
        let config = ContextConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ContextConfig"));
    }

    // ---- Clone ----

    #[test]
    fn context_config_clone() {
        let config = ContextConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.current_context, config.current_context);
        assert_eq!(cloned.contexts.len(), config.contexts.len());
    }
}
