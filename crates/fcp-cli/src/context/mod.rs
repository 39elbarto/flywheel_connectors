//! `fcp context` command implementation.
//!
//! Manages mesh contexts for multi-mesh operation, similar to `kubectl config`.
//!
//! Configuration is stored at `~/.fcp/contexts.toml` (or `$FCP_CONFIG_DIR/contexts.toml`).

pub mod types;

use anyhow::{Result, bail};
use clap::{Args, Subcommand};

use types::{ContextConfig, ContextListOutput, ContextSummary, MeshContext};

/// Arguments for the `fcp context` command.
#[derive(Args, Debug)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub command: ContextCommands,
}

/// Context management subcommands.
#[derive(Subcommand, Debug)]
pub enum ContextCommands {
    /// List all available contexts.
    List {
        /// Output JSON instead of human-readable format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Show the current active context name.
    Current {
        /// Output JSON instead of human-readable format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Switch to a different context.
    Use {
        /// Context name to switch to.
        name: String,
    },

    /// Create a new context.
    Create(CreateContextArgs),

    /// Remove a context.
    Delete {
        /// Context name to delete.
        name: String,
    },

    /// Rename a context.
    Rename {
        /// Current context name.
        old_name: String,
        /// New context name.
        new_name: String,
    },
}

/// Arguments for creating a new context.
#[derive(Args, Debug)]
pub struct CreateContextArgs {
    /// Context name (must be unique).
    pub name: String,

    /// Mesh endpoint (e.g., `unix:///var/run/fcp/node.sock`,
    /// `tcp://192.168.1.100:9000`).
    #[arg(long)]
    pub endpoint: String,

    /// Default zone for this context.
    #[arg(long)]
    pub zone: Option<String>,

    /// Path to node identity key file.
    #[arg(long)]
    pub identity: Option<std::path::PathBuf>,

    /// Set as the current context immediately.
    #[arg(long, default_value_t = false)]
    pub set_current: bool,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run the context command.
pub fn run(args: &ContextArgs) -> Result<()> {
    match &args.command {
        ContextCommands::List { json } => cmd_list(*json),
        ContextCommands::Current { json } => cmd_current(*json),
        ContextCommands::Use { name } => cmd_use(name),
        ContextCommands::Create(create_args) => cmd_create(create_args),
        ContextCommands::Delete { name } => cmd_delete(name),
        ContextCommands::Rename { old_name, new_name } => cmd_rename(old_name, new_name),
    }
}

fn cmd_list(json: bool) -> Result<()> {
    let config = ContextConfig::load_or_default()?;

    if json {
        let output = ContextListOutput {
            schema_version: ContextConfig::SCHEMA_VERSION.to_string(),
            current_context: config.current_context.clone(),
            contexts: config
                .contexts
                .iter()
                .map(|(name, ctx)| ContextSummary {
                    name: name.clone(),
                    active: *name == config.current_context,
                    endpoint: ctx.endpoint.clone(),
                    default_zone: ctx.default_zone.clone(),
                })
                .collect(),
        };
        let json_str = serde_json::to_string_pretty(&output)?;
        println!("{json_str}");
    } else {
        if config.contexts.is_empty() {
            println!("No contexts configured.");
            println!("Create one with: fcp context create <name> --endpoint <endpoint>");
            return Ok(());
        }
        for (name, ctx) in &config.contexts {
            let marker = if *name == config.current_context {
                "*"
            } else {
                " "
            };
            let zone_info = ctx
                .default_zone
                .as_deref()
                .map_or(String::new(), |z| format!(" (zone: {z})"));
            println!("{marker} {name} -> {}{zone_info}", ctx.endpoint);
        }
    }

    Ok(())
}

fn cmd_current(json: bool) -> Result<()> {
    let config = ContextConfig::load_or_default()?;

    if json {
        let output = serde_json::json!({
            "current_context": config.current_context,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", config.current_context);
    }

    Ok(())
}

fn cmd_use(name: &str) -> Result<()> {
    let mut config = ContextConfig::load_or_default()?;

    if !config.contexts.contains_key(name) {
        let available: Vec<&str> = config.contexts.keys().map(String::as_str).collect();
        bail!(
            "context {name:?} not found. Available contexts: {}",
            available.join(", ")
        );
    }

    config.current_context = name.to_string();
    config.save()?;
    println!("Switched to context: {name}");

    Ok(())
}

fn cmd_create(args: &CreateContextArgs) -> Result<()> {
    let mut config = ContextConfig::load_or_default()?;

    if config.contexts.contains_key(&args.name) {
        bail!(
            "context {:?} already exists. Use a different name or delete it first.",
            args.name
        );
    }

    let ctx = MeshContext {
        name: args.name.clone(),
        endpoint: args.endpoint.clone(),
        default_zone: args.zone.clone(),
        node_identity: args.identity.clone(),
        config_overrides: std::collections::BTreeMap::new(),
    };

    config.contexts.insert(args.name.clone(), ctx);

    if args.set_current {
        config.current_context.clone_from(&args.name);
    }

    config.save()?;

    if args.json {
        let output = serde_json::json!({
            "created": args.name,
            "endpoint": args.endpoint,
            "set_current": args.set_current,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Created context: {}", args.name);
        if args.set_current {
            println!("Set as current context.");
        }
    }

    Ok(())
}

fn cmd_delete(name: &str) -> Result<()> {
    let mut config = ContextConfig::load_or_default()?;

    if !config.contexts.contains_key(name) {
        bail!("context {name:?} not found");
    }

    if config.current_context == name {
        bail!(
            "cannot delete the current context {name:?}. Switch to another context first with: fcp context use <other>"
        );
    }

    config.contexts.remove(name);
    config.save()?;
    println!("Deleted context: {name}");

    Ok(())
}

fn cmd_rename(old_name: &str, new_name: &str) -> Result<()> {
    let mut config = ContextConfig::load_or_default()?;

    if !config.contexts.contains_key(old_name) {
        bail!("context {old_name:?} not found");
    }

    if config.contexts.contains_key(new_name) {
        bail!("context {new_name:?} already exists");
    }

    let mut ctx = config
        .contexts
        .remove(old_name)
        .expect("checked existence above");
    ctx.name = new_name.to_string();
    config.contexts.insert(new_name.to_string(), ctx);

    if config.current_context == old_name {
        config.current_context = new_name.to_string();
    }

    config.save()?;
    println!("Renamed context: {old_name} -> {new_name}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_config() -> ContextConfig {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "prod".to_string(),
            MeshContext {
                name: "prod".to_string(),
                endpoint: "tcp://prod:9000".to_string(),
                default_zone: Some("z:work".to_string()),
                node_identity: None,
                config_overrides: BTreeMap::new(),
            },
        );
        contexts.insert(
            "staging".to_string(),
            MeshContext {
                name: "staging".to_string(),
                endpoint: "tcp://staging:9000".to_string(),
                default_zone: None,
                node_identity: None,
                config_overrides: BTreeMap::new(),
            },
        );
        contexts.insert(
            "local".to_string(),
            MeshContext {
                name: "local".to_string(),
                endpoint: "unix:///tmp/fcp-dev.sock".to_string(),
                default_zone: Some("z:dev".to_string()),
                node_identity: None,
                config_overrides: BTreeMap::new(),
            },
        );
        ContextConfig {
            current_context: "staging".to_string(),
            contexts,
        }
    }

    #[test]
    fn roundtrip_toml_serialization() {
        let config = test_config();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let deserialized: ContextConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(deserialized.current_context, "staging");
        assert_eq!(deserialized.contexts.len(), 3);
        assert_eq!(deserialized.contexts["prod"].endpoint, "tcp://prod:9000");
    }

    #[test]
    fn default_config_has_local_context() {
        let config = ContextConfig::default();
        assert_eq!(config.current_context, "local");
        assert!(config.contexts.contains_key("local"));
        assert_eq!(
            config.contexts["local"].endpoint,
            "unix:///tmp/fcp-dev.sock"
        );
    }

    #[test]
    #[allow(unsafe_code)]
    fn config_path_respects_env_var() {
        // SAFETY: This test runs single-threaded; no concurrent env reads possible.
        unsafe { std::env::set_var("FCP_CONFIG_DIR", "/tmp/fcp-test-config") };
        let path = ContextConfig::config_path().unwrap();
        assert_eq!(
            path,
            std::path::PathBuf::from("/tmp/fcp-test-config/contexts.toml")
        );
        // SAFETY: This test runs single-threaded; no concurrent env reads possible.
        unsafe { std::env::remove_var("FCP_CONFIG_DIR") };
    }

    #[test]
    fn context_list_output_serialization() {
        let output = ContextListOutput {
            schema_version: "1.0.0".to_string(),
            current_context: "staging".to_string(),
            contexts: vec![
                ContextSummary {
                    name: "prod".to_string(),
                    active: false,
                    endpoint: "tcp://prod:9000".to_string(),
                    default_zone: Some("z:work".to_string()),
                },
                ContextSummary {
                    name: "staging".to_string(),
                    active: true,
                    endpoint: "tcp://staging:9000".to_string(),
                    default_zone: None,
                },
            ],
        };

        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["current_context"], "staging");
        assert_eq!(json["contexts"].as_array().unwrap().len(), 2);
        assert!(json["contexts"][1]["active"].as_bool().unwrap());
    }

    // ── test_config validation ──────────────────────────────────────────

    #[test]
    fn test_config_has_three_contexts() {
        let config = test_config();
        assert_eq!(config.contexts.len(), 3);
    }

    #[test]
    fn test_config_current_is_staging() {
        let config = test_config();
        assert_eq!(config.current_context, "staging");
    }

    #[test]
    fn test_config_contains_expected_names() {
        let config = test_config();
        assert!(config.contexts.contains_key("prod"));
        assert!(config.contexts.contains_key("staging"));
        assert!(config.contexts.contains_key("local"));
    }

    #[test]
    fn test_config_prod_has_zone() {
        let config = test_config();
        let prod = &config.contexts["prod"];
        assert_eq!(prod.default_zone.as_deref(), Some("z:work"));
    }

    #[test]
    fn test_config_staging_no_zone() {
        let config = test_config();
        let staging = &config.contexts["staging"];
        assert!(staging.default_zone.is_none());
    }

    #[test]
    fn test_config_local_unix_socket() {
        let config = test_config();
        let local = &config.contexts["local"];
        assert!(local.endpoint.starts_with("unix://"));
    }

    // ── BTreeMap ordering ───────────────────────────────────────────────

    #[test]
    fn test_config_contexts_sorted() {
        let config = test_config();
        let names: Vec<&String> = config.contexts.keys().collect();
        assert_eq!(names, vec!["local", "prod", "staging"]);
    }

    // ── TOML roundtrip preserves all fields ─────────────────────────────

    #[test]
    fn test_config_toml_roundtrip_preserves_zones() {
        let config = test_config();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let back: ContextConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            back.contexts["prod"].default_zone,
            config.contexts["prod"].default_zone
        );
        assert_eq!(
            back.contexts["local"].default_zone,
            config.contexts["local"].default_zone
        );
        assert!(back.contexts["staging"].default_zone.is_none());
    }

    #[test]
    fn test_config_toml_roundtrip_preserves_endpoints() {
        let config = test_config();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let back: ContextConfig = toml::from_str(&toml_str).unwrap();
        for (name, ctx) in &config.contexts {
            assert_eq!(back.contexts[name].endpoint, ctx.endpoint);
        }
    }

    // ── ContextListOutput edge cases ────────────────────────────────────

    #[test]
    fn context_list_output_empty_contexts() {
        let output = ContextListOutput {
            schema_version: "1.0.0".to_string(),
            current_context: "none".to_string(),
            contexts: vec![],
        };
        let json = serde_json::to_string(&output).unwrap();
        let back: ContextListOutput = serde_json::from_str(&json).unwrap();
        assert!(back.contexts.is_empty());
    }

    #[test]
    fn context_summary_skip_serializing_none_zone() {
        let summary = ContextSummary {
            name: "test".to_string(),
            active: false,
            endpoint: "tcp://test:9000".to_string(),
            default_zone: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("default_zone"));
    }

    #[test]
    fn context_summary_includes_zone_when_present() {
        let summary = ContextSummary {
            name: "test".to_string(),
            active: true,
            endpoint: "tcp://test:9000".to_string(),
            default_zone: Some("z:work".to_string()),
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("default_zone"));
        assert!(json.contains("z:work"));
    }

    // ── CreateContextArgs ───────────────────────────────────────────────

    #[test]
    fn create_context_args_debug() {
        let args = CreateContextArgs {
            name: "test-ctx".to_string(),
            endpoint: "tcp://127.0.0.1:9000".to_string(),
            zone: Some("z:dev".to_string()),
            identity: None,
            set_current: false,
            json: false,
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("test-ctx"));
        assert!(dbg.contains("tcp://127.0.0.1:9000"));
    }

    #[test]
    fn create_context_args_all_fields() {
        let args = CreateContextArgs {
            name: "full".to_string(),
            endpoint: "unix:///run/fcp.sock".to_string(),
            zone: Some("z:owner".to_string()),
            identity: Some(std::path::PathBuf::from("/keys/node.key")),
            set_current: true,
            json: true,
        };
        assert!(args.set_current);
        assert!(args.json);
        assert_eq!(args.zone.as_deref(), Some("z:owner"));
    }

    // ── ContextCommands debug ───────────────────────────────────────────

    #[test]
    fn context_commands_list_debug() {
        let cmd = ContextCommands::List { json: true };
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("List"));
    }

    #[test]
    fn context_commands_use_debug() {
        let cmd = ContextCommands::Use {
            name: "prod".to_string(),
        };
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("prod"));
    }

    #[test]
    fn context_commands_delete_debug() {
        let cmd = ContextCommands::Delete {
            name: "staging".to_string(),
        };
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("staging"));
    }

    #[test]
    fn context_commands_rename_debug() {
        let cmd = ContextCommands::Rename {
            old_name: "old".to_string(),
            new_name: "new".to_string(),
        };
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("old"));
        assert!(dbg.contains("new"));
    }
}
