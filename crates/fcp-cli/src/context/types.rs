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
