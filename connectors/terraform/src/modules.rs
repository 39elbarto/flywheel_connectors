//! Terraform module management and dependency resolution.
//!
//! Provides types and utilities for parsing Terraform module sources,
//! building module dependency graphs, and enforcing init policies.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ProviderRequirement
// ---------------------------------------------------------------------------

/// A required Terraform provider with version constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRequirement {
    /// Provider local name (e.g. "aws").
    pub name: String,
    /// Registry source address (e.g. "hashicorp/aws").
    pub source: String,
    /// Version constraint expression (e.g. "~> 5.0").
    pub version_constraint: Option<String>,
    /// Minimum required Terraform version for this provider.
    pub required_version: Option<String>,
}

impl fmt::Display for ProviderRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.source)?;
        if let Some(vc) = &self.version_constraint {
            write!(f, " {vc}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ModuleSource
// ---------------------------------------------------------------------------

/// The origin of a Terraform module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ModuleSource {
    /// Terraform Registry module.
    Registry {
        hostname: String,
        namespace: String,
        name: String,
        provider: String,
    },
    /// Git repository.
    Git {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ref_spec: Option<String>,
    },
    /// Local filesystem path.
    Local { path: String },
    /// HTTP/HTTPS URL archive.
    Http { url: String },
}

impl ModuleSource {
    /// Returns the source type as a static string.
    #[must_use]
    pub const fn source_type(&self) -> &'static str {
        match self {
            Self::Registry { .. } => "registry",
            Self::Git { .. } => "git",
            Self::Local { .. } => "local",
            Self::Http { .. } => "http",
        }
    }

    /// Parse a Terraform module source string into a `ModuleSource`.
    ///
    /// Heuristics (matching Terraform CLI behaviour):
    /// - Starts with `./` or `../` => Local
    /// - Starts with `git::` => Git (strip prefix)
    /// - Starts with `https://` or `http://` => Http
    /// - Contains `github.com` or `bitbucket.org` => Git
    /// - Has three slash-separated segments (`namespace/name/provider`) with an
    ///   optional `hostname/` prefix => Registry
    /// - Otherwise falls back to Local.
    #[must_use]
    pub fn parse(source_str: &str) -> Self {
        let s = source_str.trim();

        // Local paths
        if s.starts_with("./") || s.starts_with("../") {
            return Self::Local {
                path: s.to_string(),
            };
        }

        // Explicit git:: prefix
        if let Some(stripped) = s.strip_prefix("git::") {
            let (url, ref_spec) = Self::split_git_ref(stripped);
            return Self::Git { url, ref_spec };
        }

        // HTTP(S) archives
        if s.starts_with("https://") || s.starts_with("http://") {
            // GitHub / Bitbucket URLs are treated as git
            if s.contains("github.com") || s.contains("bitbucket.org") {
                let (url, ref_spec) = Self::split_git_ref(s);
                return Self::Git { url, ref_spec };
            }
            return Self::Http { url: s.to_string() };
        }

        // Bare github.com / bitbucket.org references
        if s.starts_with("github.com") || s.starts_with("bitbucket.org") {
            let (url, ref_spec) = Self::split_git_ref(&format!("https://{s}"));
            return Self::Git { url, ref_spec };
        }

        // Registry: try `hostname/namespace/name/provider` (4 parts) or
        // `namespace/name/provider` (3 parts, default hostname).
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() == 3 {
            return Self::Registry {
                hostname: "registry.terraform.io".to_string(),
                namespace: parts[0].to_string(),
                name: parts[1].to_string(),
                provider: parts[2].to_string(),
            };
        }
        if parts.len() >= 4 {
            return Self::Registry {
                hostname: parts[0].to_string(),
                namespace: parts[1].to_string(),
                name: parts[2].to_string(),
                provider: parts[3].to_string(),
            };
        }

        // Fallback: treat as local
        Self::Local {
            path: s.to_string(),
        }
    }

    /// Split a git URL on `?ref=...` or `//...?ref=...`.
    fn split_git_ref(url: &str) -> (String, Option<String>) {
        if let Some(idx) = url.find("?ref=") {
            let base = &url[..idx];
            let ref_spec = &url[idx + 5..];
            (
                base.to_string(),
                if ref_spec.is_empty() {
                    None
                } else {
                    Some(ref_spec.to_string())
                },
            )
        } else {
            (url.to_string(), None)
        }
    }
}

impl fmt::Display for ModuleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry {
                hostname,
                namespace,
                name,
                provider,
            } => {
                write!(f, "{hostname}/{namespace}/{name}/{provider}")
            }
            Self::Git { url, ref_spec } => {
                write!(f, "git::{url}")?;
                if let Some(r) = ref_spec {
                    write!(f, "?ref={r}")?;
                }
                Ok(())
            }
            Self::Local { path } => write!(f, "{path}"),
            Self::Http { url } => write!(f, "{url}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ModuleEntry
// ---------------------------------------------------------------------------

/// A single module call in a Terraform configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleEntry {
    /// The module block key (e.g. "network").
    pub key: String,
    /// Resolved source.
    pub source: ModuleSource,
    /// Optional version constraint (registry modules).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional subdirectory within the source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
}

impl fmt::Display for ModuleEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "module.{} ({})", self.key, self.source)?;
        if let Some(v) = &self.version {
            write!(f, " v{v}")?;
        }
        if let Some(d) = &self.dir {
            write!(f, " dir={d}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RootModule
// ---------------------------------------------------------------------------

/// The root Terraform configuration module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootModule {
    /// Filesystem path to the root module.
    pub path: String,
    /// Optional backend type (e.g. "s3", "remote").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
}

impl fmt::Display for RootModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "root({})", self.path)?;
        if let Some(b) = &self.backend {
            write!(f, " backend={b}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ModuleGraph
// ---------------------------------------------------------------------------

/// A dependency graph of Terraform modules and providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleGraph {
    pub root_module: RootModule,
    pub modules: Vec<ModuleEntry>,
    pub providers: Vec<ProviderRequirement>,
}

impl ModuleGraph {
    /// Parse a `ModuleGraph` from a JSON value.
    ///
    /// Expects a shape like:
    /// ```json
    /// {
    ///   "root": { "path": ".", "backend": "s3" },
    ///   "modules": [ { "key": "...", "source": "...", "version": "..." } ],
    ///   "providers": [ { "name": "...", "source": "...", "version_constraint": "..." } ]
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `Err` if required fields are missing or malformed.
    pub fn from_json(json: &serde_json::Value) -> Result<Self, String> {
        // Root module
        let root_val = json.get("root").ok_or("missing 'root' field")?;
        let root_path = root_val
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or("missing 'root.path' field")?
            .to_string();
        let root_backend = root_val
            .get("backend")
            .and_then(serde_json::Value::as_str)
            .map(String::from);
        let root_module = RootModule {
            path: root_path,
            backend: root_backend,
        };

        // Modules
        let modules = if let Some(arr) = json.get("modules").and_then(serde_json::Value::as_array) {
            arr.iter()
                .enumerate()
                .map(|(i, m)| {
                    let key = m
                        .get("key")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| format!("modules[{i}]: missing 'key'"))?
                        .to_string();
                    let source_str = m
                        .get("source")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| format!("modules[{i}]: missing 'source'"))?;
                    let source = ModuleSource::parse(source_str);
                    let version = m
                        .get("version")
                        .and_then(serde_json::Value::as_str)
                        .map(String::from);
                    let dir = m
                        .get("dir")
                        .and_then(serde_json::Value::as_str)
                        .map(String::from);
                    Ok(ModuleEntry {
                        key,
                        source,
                        version,
                        dir,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?
        } else {
            Vec::new()
        };

        // Providers
        let providers =
            if let Some(arr) = json.get("providers").and_then(serde_json::Value::as_array) {
                arr.iter()
                    .enumerate()
                    .map(|(i, p)| {
                        let name = p
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| format!("providers[{i}]: missing 'name'"))?
                            .to_string();
                        let source = p
                            .get("source")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| format!("providers[{i}]: missing 'source'"))?
                            .to_string();
                        let version_constraint = p
                            .get("version_constraint")
                            .and_then(serde_json::Value::as_str)
                            .map(String::from);
                        let required_version = p
                            .get("required_version")
                            .and_then(serde_json::Value::as_str)
                            .map(String::from);
                        Ok(ProviderRequirement {
                            name,
                            source,
                            version_constraint,
                            required_version,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?
            } else {
                Vec::new()
            };

        Ok(Self {
            root_module,
            modules,
            providers,
        })
    }

    /// Compute a summary of the module graph.
    #[must_use]
    pub fn summary(&self) -> ModuleGraphSummary {
        let mut has_remote = false;
        let mut has_local = false;
        let mut registry_count = 0u32;
        let mut git_count = 0u32;

        for m in &self.modules {
            match &m.source {
                ModuleSource::Registry { .. } => {
                    has_remote = true;
                    registry_count += 1;
                }
                ModuleSource::Git { .. } => {
                    has_remote = true;
                    git_count += 1;
                }
                ModuleSource::Local { .. } => {
                    has_local = true;
                }
                ModuleSource::Http { .. } => {
                    has_remote = true;
                }
            }
        }

        ModuleGraphSummary {
            module_count: self.modules.len() as u32,
            provider_count: self.providers.len() as u32,
            has_remote_modules: has_remote,
            has_local_modules: has_local,
            registry_modules: registry_count,
            git_modules: git_count,
        }
    }

    /// Look up a module entry by its key.
    #[must_use]
    pub fn find_module(&self, key: &str) -> Option<&ModuleEntry> {
        self.modules.iter().find(|m| m.key == key)
    }

    /// Return all modules whose source matches the given type string.
    ///
    /// Valid values: `"registry"`, `"git"`, `"local"`, `"http"`.
    #[must_use]
    pub fn modules_by_source_type(&self, source_type: &str) -> Vec<&ModuleEntry> {
        self.modules
            .iter()
            .filter(|m| m.source.source_type() == source_type)
            .collect()
    }

    /// Return the slice of required providers.
    #[must_use]
    pub fn required_providers(&self) -> &[ProviderRequirement] {
        &self.providers
    }
}

impl fmt::Display for ModuleGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ModuleGraph({}, {} modules, {} providers)",
            self.root_module.path,
            self.modules.len(),
            self.providers.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ModuleGraphSummary
// ---------------------------------------------------------------------------

/// Aggregated statistics for a `ModuleGraph`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleGraphSummary {
    pub module_count: u32,
    pub provider_count: u32,
    pub has_remote_modules: bool,
    pub has_local_modules: bool,
    pub registry_modules: u32,
    pub git_modules: u32,
}

impl fmt::Display for ModuleGraphSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} modules ({} registry, {} git), {} providers",
            self.module_count, self.registry_modules, self.git_modules, self.provider_count
        )
    }
}

// ---------------------------------------------------------------------------
// InitPolicy
// ---------------------------------------------------------------------------

/// Policy governing whether `terraform init` may download remote modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitPolicy {
    /// Report what would be done without downloading.
    DryRun,
    /// Allow downloading remote modules.
    AllowDownload,
    /// Deny all remote downloads.
    Deny,
}

impl InitPolicy {
    /// Whether this policy permits downloading remote modules.
    #[must_use]
    pub const fn is_download_allowed(self) -> bool {
        matches!(self, Self::AllowDownload)
    }

    /// Evaluate whether initialisation should proceed given the presence of
    /// remote modules.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the policy is `Deny` and `has_remote_modules` is true,
    /// or if the policy is `DryRun` and remote modules would need downloading.
    pub fn evaluate(self, has_remote_modules: bool) -> Result<(), String> {
        match self {
            Self::AllowDownload => Ok(()),
            Self::Deny => {
                if has_remote_modules {
                    Err(
                        "init denied: configuration contains remote modules but policy is Deny"
                            .into(),
                    )
                } else {
                    Ok(())
                }
            }
            Self::DryRun => {
                if has_remote_modules {
                    Err("dry-run: remote modules detected, download would be required".into())
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl fmt::Display for InitPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DryRun => write!(f, "dry-run"),
            Self::AllowDownload => write!(f, "allow-download"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // ModuleSource::parse — registry variants
    // -----------------------------------------------------------------------

    #[test]
    fn parse_registry_three_part() {
        let src = ModuleSource::parse("hashicorp/consul/aws");
        assert_eq!(
            src,
            ModuleSource::Registry {
                hostname: "registry.terraform.io".to_string(),
                namespace: "hashicorp".to_string(),
                name: "consul".to_string(),
                provider: "aws".to_string(),
            }
        );
        assert_eq!(src.source_type(), "registry");
    }

    #[test]
    fn parse_registry_four_part_custom_hostname() {
        let src = ModuleSource::parse("app.terraform.io/myorg/vpc/aws");
        assert_eq!(
            src,
            ModuleSource::Registry {
                hostname: "app.terraform.io".to_string(),
                namespace: "myorg".to_string(),
                name: "vpc".to_string(),
                provider: "aws".to_string(),
            }
        );
    }

    #[test]
    fn parse_registry_with_full_hostname() {
        let src = ModuleSource::parse("registry.terraform.io/hashicorp/consul/aws");
        assert_eq!(
            src,
            ModuleSource::Registry {
                hostname: "registry.terraform.io".to_string(),
                namespace: "hashicorp".to_string(),
                name: "consul".to_string(),
                provider: "aws".to_string(),
            }
        );
    }

    #[test]
    fn parse_registry_source_type() {
        let src = ModuleSource::parse("hashicorp/vault/aws");
        assert_eq!(src.source_type(), "registry");
    }

    // -----------------------------------------------------------------------
    // ModuleSource::parse — git variants
    // -----------------------------------------------------------------------

    #[test]
    fn parse_git_explicit_prefix() {
        let src = ModuleSource::parse("git::https://example.com/module.git");
        assert_eq!(
            src,
            ModuleSource::Git {
                url: "https://example.com/module.git".to_string(),
                ref_spec: None,
            }
        );
        assert_eq!(src.source_type(), "git");
    }

    #[test]
    fn parse_git_explicit_with_ref() {
        let src = ModuleSource::parse("git::https://example.com/module.git?ref=v1.2.0");
        assert_eq!(
            src,
            ModuleSource::Git {
                url: "https://example.com/module.git".to_string(),
                ref_spec: Some("v1.2.0".to_string()),
            }
        );
    }

    #[test]
    fn parse_git_github_bare() {
        let src = ModuleSource::parse("github.com/hashicorp/example");
        match &src {
            ModuleSource::Git { url, ref_spec } => {
                assert!(url.contains("github.com"));
                assert!(ref_spec.is_none());
            }
            other => panic!("expected Git, got {other:?}"),
        }
        assert_eq!(src.source_type(), "git");
    }

    #[test]
    fn parse_git_github_https() {
        let src = ModuleSource::parse("https://github.com/hashicorp/terraform-aws-consul");
        assert_eq!(src.source_type(), "git");
    }

    #[test]
    fn parse_git_bitbucket_bare() {
        let src = ModuleSource::parse("bitbucket.org/hashicorp/tf-mod");
        assert_eq!(src.source_type(), "git");
    }

    #[test]
    fn parse_git_bitbucket_https() {
        let src = ModuleSource::parse("https://bitbucket.org/hashicorp/tf-mod");
        assert_eq!(src.source_type(), "git");
    }

    #[test]
    fn parse_git_ssh_prefix() {
        let src = ModuleSource::parse("git::ssh://git@github.com/org/mod.git");
        assert_eq!(
            src,
            ModuleSource::Git {
                url: "ssh://git@github.com/org/mod.git".to_string(),
                ref_spec: None,
            }
        );
    }

    #[test]
    fn parse_git_ref_branch() {
        let src = ModuleSource::parse("git::https://example.com/repo.git?ref=feature/branch");
        match src {
            ModuleSource::Git { ref_spec, .. } => {
                assert_eq!(ref_spec, Some("feature/branch".to_string()));
            }
            other => panic!("expected Git, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // ModuleSource::parse — local variants
    // -----------------------------------------------------------------------

    #[test]
    fn parse_local_relative_dot() {
        let src = ModuleSource::parse("./modules/network");
        assert_eq!(
            src,
            ModuleSource::Local {
                path: "./modules/network".to_string(),
            }
        );
        assert_eq!(src.source_type(), "local");
    }

    #[test]
    fn parse_local_relative_dotdot() {
        let src = ModuleSource::parse("../shared/vpc");
        assert_eq!(
            src,
            ModuleSource::Local {
                path: "../shared/vpc".to_string(),
            }
        );
    }

    #[test]
    fn parse_local_single_segment_fallback() {
        let src = ModuleSource::parse("mymodule");
        assert_eq!(
            src,
            ModuleSource::Local {
                path: "mymodule".to_string(),
            }
        );
    }

    #[test]
    fn parse_local_two_segments_fallback() {
        let src = ModuleSource::parse("modules/network");
        assert_eq!(src.source_type(), "local");
    }

    // -----------------------------------------------------------------------
    // ModuleSource::parse — http variants
    // -----------------------------------------------------------------------

    #[test]
    fn parse_http_archive() {
        let src = ModuleSource::parse("https://example.com/modules/vpc.zip");
        assert_eq!(
            src,
            ModuleSource::Http {
                url: "https://example.com/modules/vpc.zip".to_string(),
            }
        );
        assert_eq!(src.source_type(), "http");
    }

    #[test]
    fn parse_http_plain() {
        let src = ModuleSource::parse("http://internal.corp/modules/db.tar.gz");
        assert_eq!(src.source_type(), "http");
    }

    // -----------------------------------------------------------------------
    // ModuleSource::parse — edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn parse_trims_whitespace() {
        let src = ModuleSource::parse("  ./modules/trimmed  ");
        assert_eq!(
            src,
            ModuleSource::Local {
                path: "./modules/trimmed".to_string(),
            }
        );
    }

    #[test]
    fn parse_empty_ref_treated_as_none() {
        let src = ModuleSource::parse("git::https://example.com/repo.git?ref=");
        match src {
            ModuleSource::Git { ref_spec, .. } => {
                assert!(ref_spec.is_none());
            }
            other => panic!("expected Git, got {other:?}"),
        }
    }

    #[test]
    fn parse_empty_string_is_local() {
        let src = ModuleSource::parse("");
        assert_eq!(src.source_type(), "local");
    }

    // -----------------------------------------------------------------------
    // ModuleSource Display
    // -----------------------------------------------------------------------

    #[test]
    fn display_registry() {
        let src = ModuleSource::Registry {
            hostname: "registry.terraform.io".into(),
            namespace: "hashicorp".into(),
            name: "consul".into(),
            provider: "aws".into(),
        };
        assert_eq!(
            src.to_string(),
            "registry.terraform.io/hashicorp/consul/aws"
        );
    }

    #[test]
    fn display_git_no_ref() {
        let src = ModuleSource::Git {
            url: "https://example.com/mod.git".into(),
            ref_spec: None,
        };
        assert_eq!(src.to_string(), "git::https://example.com/mod.git");
    }

    #[test]
    fn display_git_with_ref() {
        let src = ModuleSource::Git {
            url: "https://example.com/mod.git".into(),
            ref_spec: Some("v1.0".into()),
        };
        assert_eq!(src.to_string(), "git::https://example.com/mod.git?ref=v1.0");
    }

    #[test]
    fn display_local() {
        let src = ModuleSource::Local {
            path: "./modules/net".into(),
        };
        assert_eq!(src.to_string(), "./modules/net");
    }

    #[test]
    fn display_http() {
        let src = ModuleSource::Http {
            url: "https://example.com/mod.zip".into(),
        };
        assert_eq!(src.to_string(), "https://example.com/mod.zip");
    }

    // -----------------------------------------------------------------------
    // ModuleSource source_type
    // -----------------------------------------------------------------------

    #[test]
    fn source_type_registry() {
        let src = ModuleSource::Registry {
            hostname: "r".into(),
            namespace: "n".into(),
            name: "m".into(),
            provider: "p".into(),
        };
        assert_eq!(src.source_type(), "registry");
    }

    #[test]
    fn source_type_git() {
        let src = ModuleSource::Git {
            url: "x".into(),
            ref_spec: None,
        };
        assert_eq!(src.source_type(), "git");
    }

    #[test]
    fn source_type_local() {
        let src = ModuleSource::Local { path: ".".into() };
        assert_eq!(src.source_type(), "local");
    }

    #[test]
    fn source_type_http() {
        let src = ModuleSource::Http { url: "u".into() };
        assert_eq!(src.source_type(), "http");
    }

    // -----------------------------------------------------------------------
    // ModuleEntry Display
    // -----------------------------------------------------------------------

    #[test]
    fn module_entry_display_minimal() {
        let e = ModuleEntry {
            key: "net".into(),
            source: ModuleSource::Local {
                path: "./modules/net".into(),
            },
            version: None,
            dir: None,
        };
        assert!(e.to_string().contains("module.net"));
    }

    #[test]
    fn module_entry_display_with_version_and_dir() {
        let e = ModuleEntry {
            key: "consul".into(),
            source: ModuleSource::Registry {
                hostname: "registry.terraform.io".into(),
                namespace: "hashicorp".into(),
                name: "consul".into(),
                provider: "aws".into(),
            },
            version: Some("0.1.0".into()),
            dir: Some("modules/consul-cluster".into()),
        };
        let s = e.to_string();
        assert!(s.contains("module.consul"));
        assert!(s.contains("v0.1.0"));
        assert!(s.contains("dir=modules/consul-cluster"));
    }

    // -----------------------------------------------------------------------
    // RootModule Display
    // -----------------------------------------------------------------------

    #[test]
    fn root_module_display_no_backend() {
        let r = RootModule {
            path: ".".into(),
            backend: None,
        };
        assert_eq!(r.to_string(), "root(.)");
    }

    #[test]
    fn root_module_display_with_backend() {
        let r = RootModule {
            path: "/infra".into(),
            backend: Some("s3".into()),
        };
        assert_eq!(r.to_string(), "root(/infra) backend=s3");
    }

    // -----------------------------------------------------------------------
    // ModuleGraph::from_json — happy paths
    // -----------------------------------------------------------------------

    fn sample_json() -> serde_json::Value {
        json!({
            "root": { "path": ".", "backend": "s3" },
            "modules": [
                { "key": "network", "source": "hashicorp/vpc/aws", "version": "3.0.0" },
                { "key": "database", "source": "./modules/rds" },
                { "key": "cache", "source": "git::https://example.com/cache.git?ref=v2.1" },
                { "key": "cdn", "source": "https://cdn.example.com/module.zip" },
            ],
            "providers": [
                { "name": "aws", "source": "hashicorp/aws", "version_constraint": "~> 5.0" },
                { "name": "random", "source": "hashicorp/random" },
            ]
        })
    }

    #[test]
    fn from_json_parses_root() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        assert_eq!(g.root_module.path, ".");
        assert_eq!(g.root_module.backend, Some("s3".to_string()));
    }

    #[test]
    fn from_json_parses_modules() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        assert_eq!(g.modules.len(), 4);
    }

    #[test]
    fn from_json_parses_providers() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        assert_eq!(g.providers.len(), 2);
        assert_eq!(g.providers[0].name, "aws");
        assert_eq!(g.providers[0].version_constraint, Some("~> 5.0".into()));
        assert!(g.providers[1].version_constraint.is_none());
    }

    #[test]
    fn from_json_module_sources_correct() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        assert_eq!(g.modules[0].source.source_type(), "registry");
        assert_eq!(g.modules[1].source.source_type(), "local");
        assert_eq!(g.modules[2].source.source_type(), "git");
        assert_eq!(g.modules[3].source.source_type(), "http");
    }

    #[test]
    fn from_json_module_versions() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        assert_eq!(g.modules[0].version, Some("3.0.0".into()));
        assert!(g.modules[1].version.is_none());
    }

    #[test]
    fn from_json_module_dir() {
        let j = json!({
            "root": { "path": "." },
            "modules": [
                { "key": "sub", "source": "hashicorp/consul/aws", "dir": "examples/simple" }
            ]
        });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert_eq!(g.modules[0].dir, Some("examples/simple".into()));
    }

    #[test]
    fn from_json_no_modules_key() {
        let j = json!({ "root": { "path": "." } });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert!(g.modules.is_empty());
        assert!(g.providers.is_empty());
    }

    #[test]
    fn from_json_empty_modules_array() {
        let j = json!({ "root": { "path": "." }, "modules": [] });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert!(g.modules.is_empty());
    }

    #[test]
    fn from_json_no_backend() {
        let j = json!({ "root": { "path": "/code" } });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert!(g.root_module.backend.is_none());
    }

    // -----------------------------------------------------------------------
    // ModuleGraph::from_json — error cases
    // -----------------------------------------------------------------------

    #[test]
    fn from_json_missing_root() {
        let j = json!({ "modules": [] });
        let err = ModuleGraph::from_json(&j).unwrap_err();
        assert!(err.contains("root"));
    }

    #[test]
    fn from_json_missing_root_path() {
        let j = json!({ "root": {} });
        let err = ModuleGraph::from_json(&j).unwrap_err();
        assert!(err.contains("path"));
    }

    #[test]
    fn from_json_module_missing_key() {
        let j = json!({
            "root": { "path": "." },
            "modules": [ { "source": "hashicorp/consul/aws" } ]
        });
        let err = ModuleGraph::from_json(&j).unwrap_err();
        assert!(err.contains("key"));
    }

    #[test]
    fn from_json_module_missing_source() {
        let j = json!({
            "root": { "path": "." },
            "modules": [ { "key": "x" } ]
        });
        let err = ModuleGraph::from_json(&j).unwrap_err();
        assert!(err.contains("source"));
    }

    #[test]
    fn from_json_provider_missing_name() {
        let j = json!({
            "root": { "path": "." },
            "providers": [ { "source": "hashicorp/aws" } ]
        });
        let err = ModuleGraph::from_json(&j).unwrap_err();
        assert!(err.contains("name"));
    }

    #[test]
    fn from_json_provider_missing_source() {
        let j = json!({
            "root": { "path": "." },
            "providers": [ { "name": "aws" } ]
        });
        let err = ModuleGraph::from_json(&j).unwrap_err();
        assert!(err.contains("source"));
    }

    // -----------------------------------------------------------------------
    // ModuleGraph::summary
    // -----------------------------------------------------------------------

    #[test]
    fn summary_mixed_sources() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let s = g.summary();
        assert_eq!(s.module_count, 4);
        assert_eq!(s.provider_count, 2);
        assert!(s.has_remote_modules);
        assert!(s.has_local_modules);
        assert_eq!(s.registry_modules, 1);
        assert_eq!(s.git_modules, 1);
    }

    #[test]
    fn summary_empty_graph() {
        let g = ModuleGraph {
            root_module: RootModule {
                path: ".".into(),
                backend: None,
            },
            modules: vec![],
            providers: vec![],
        };
        let s = g.summary();
        assert_eq!(s.module_count, 0);
        assert_eq!(s.provider_count, 0);
        assert!(!s.has_remote_modules);
        assert!(!s.has_local_modules);
        assert_eq!(s.registry_modules, 0);
        assert_eq!(s.git_modules, 0);
    }

    #[test]
    fn summary_only_local() {
        let g = ModuleGraph {
            root_module: RootModule {
                path: ".".into(),
                backend: None,
            },
            modules: vec![ModuleEntry {
                key: "a".into(),
                source: ModuleSource::Local { path: "./a".into() },
                version: None,
                dir: None,
            }],
            providers: vec![],
        };
        let s = g.summary();
        assert!(!s.has_remote_modules);
        assert!(s.has_local_modules);
    }

    #[test]
    fn summary_only_registry() {
        let g = ModuleGraph {
            root_module: RootModule {
                path: ".".into(),
                backend: None,
            },
            modules: vec![ModuleEntry {
                key: "r".into(),
                source: ModuleSource::Registry {
                    hostname: "r".into(),
                    namespace: "n".into(),
                    name: "m".into(),
                    provider: "p".into(),
                },
                version: None,
                dir: None,
            }],
            providers: vec![],
        };
        let s = g.summary();
        assert!(s.has_remote_modules);
        assert!(!s.has_local_modules);
        assert_eq!(s.registry_modules, 1);
    }

    #[test]
    fn summary_only_git() {
        let g = ModuleGraph {
            root_module: RootModule {
                path: ".".into(),
                backend: None,
            },
            modules: vec![ModuleEntry {
                key: "g".into(),
                source: ModuleSource::Git {
                    url: "https://example.com".into(),
                    ref_spec: None,
                },
                version: None,
                dir: None,
            }],
            providers: vec![],
        };
        let s = g.summary();
        assert!(s.has_remote_modules);
        assert_eq!(s.git_modules, 1);
    }

    #[test]
    fn summary_only_http() {
        let g = ModuleGraph {
            root_module: RootModule {
                path: ".".into(),
                backend: None,
            },
            modules: vec![ModuleEntry {
                key: "h".into(),
                source: ModuleSource::Http {
                    url: "https://example.com/m.zip".into(),
                },
                version: None,
                dir: None,
            }],
            providers: vec![],
        };
        let s = g.summary();
        assert!(s.has_remote_modules);
        assert!(!s.has_local_modules);
    }

    #[test]
    fn summary_display() {
        let s = ModuleGraphSummary {
            module_count: 5,
            provider_count: 2,
            has_remote_modules: true,
            has_local_modules: true,
            registry_modules: 3,
            git_modules: 1,
        };
        let d = s.to_string();
        assert!(d.contains("5 modules"));
        assert!(d.contains("3 registry"));
        assert!(d.contains("1 git"));
        assert!(d.contains("2 providers"));
    }

    // -----------------------------------------------------------------------
    // ModuleGraph::find_module
    // -----------------------------------------------------------------------

    #[test]
    fn find_module_existing() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let m = g.find_module("network").unwrap();
        assert_eq!(m.key, "network");
        assert_eq!(m.source.source_type(), "registry");
    }

    #[test]
    fn find_module_not_found() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        assert!(g.find_module("nonexistent").is_none());
    }

    #[test]
    fn find_module_local() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let m = g.find_module("database").unwrap();
        assert_eq!(m.source.source_type(), "local");
    }

    #[test]
    fn find_module_empty_graph() {
        let g = ModuleGraph {
            root_module: RootModule {
                path: ".".into(),
                backend: None,
            },
            modules: vec![],
            providers: vec![],
        };
        assert!(g.find_module("any").is_none());
    }

    // -----------------------------------------------------------------------
    // ModuleGraph::modules_by_source_type
    // -----------------------------------------------------------------------

    #[test]
    fn modules_by_source_type_registry() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let mods = g.modules_by_source_type("registry");
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].key, "network");
    }

    #[test]
    fn modules_by_source_type_local() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let mods = g.modules_by_source_type("local");
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].key, "database");
    }

    #[test]
    fn modules_by_source_type_git() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let mods = g.modules_by_source_type("git");
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].key, "cache");
    }

    #[test]
    fn modules_by_source_type_http() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let mods = g.modules_by_source_type("http");
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].key, "cdn");
    }

    #[test]
    fn modules_by_source_type_none() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let mods = g.modules_by_source_type("s3");
        assert!(mods.is_empty());
    }

    // -----------------------------------------------------------------------
    // ModuleGraph::required_providers
    // -----------------------------------------------------------------------

    #[test]
    fn required_providers_returns_all() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let providers = g.required_providers();
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn required_providers_empty() {
        let g = ModuleGraph {
            root_module: RootModule {
                path: ".".into(),
                backend: None,
            },
            modules: vec![],
            providers: vec![],
        };
        assert!(g.required_providers().is_empty());
    }

    #[test]
    fn provider_with_required_version() {
        let j = json!({
            "root": { "path": "." },
            "providers": [{
                "name": "aws",
                "source": "hashicorp/aws",
                "version_constraint": "~> 5.0",
                "required_version": ">= 1.5.0"
            }]
        });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert_eq!(
            g.providers[0].required_version,
            Some(">= 1.5.0".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // ModuleGraph Display
    // -----------------------------------------------------------------------

    #[test]
    fn module_graph_display() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let s = g.to_string();
        assert!(s.contains("ModuleGraph"));
        assert!(s.contains("4 modules"));
        assert!(s.contains("2 providers"));
    }

    // -----------------------------------------------------------------------
    // ProviderRequirement Display
    // -----------------------------------------------------------------------

    #[test]
    fn provider_requirement_display_with_constraint() {
        let p = ProviderRequirement {
            name: "aws".into(),
            source: "hashicorp/aws".into(),
            version_constraint: Some("~> 5.0".into()),
            required_version: None,
        };
        let s = p.to_string();
        assert!(s.contains("aws"));
        assert!(s.contains("hashicorp/aws"));
        assert!(s.contains("~> 5.0"));
    }

    #[test]
    fn provider_requirement_display_no_constraint() {
        let p = ProviderRequirement {
            name: "random".into(),
            source: "hashicorp/random".into(),
            version_constraint: None,
            required_version: None,
        };
        let s = p.to_string();
        assert!(s.contains("random"));
        assert!(!s.contains("~>"));
    }

    // -----------------------------------------------------------------------
    // InitPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn init_policy_allow_download() {
        assert!(InitPolicy::AllowDownload.is_download_allowed());
    }

    #[test]
    fn init_policy_deny_not_allowed() {
        assert!(!InitPolicy::Deny.is_download_allowed());
    }

    #[test]
    fn init_policy_dry_run_not_allowed() {
        assert!(!InitPolicy::DryRun.is_download_allowed());
    }

    #[test]
    fn init_policy_allow_download_with_remote() {
        assert!(InitPolicy::AllowDownload.evaluate(true).is_ok());
    }

    #[test]
    fn init_policy_allow_download_without_remote() {
        assert!(InitPolicy::AllowDownload.evaluate(false).is_ok());
    }

    #[test]
    fn init_policy_deny_with_remote() {
        let err = InitPolicy::Deny.evaluate(true).unwrap_err();
        assert!(err.contains("denied"));
    }

    #[test]
    fn init_policy_deny_without_remote() {
        assert!(InitPolicy::Deny.evaluate(false).is_ok());
    }

    #[test]
    fn init_policy_dry_run_with_remote() {
        let err = InitPolicy::DryRun.evaluate(true).unwrap_err();
        assert!(err.contains("dry-run"));
    }

    #[test]
    fn init_policy_dry_run_without_remote() {
        assert!(InitPolicy::DryRun.evaluate(false).is_ok());
    }

    #[test]
    fn init_policy_display_allow() {
        assert_eq!(InitPolicy::AllowDownload.to_string(), "allow-download");
    }

    #[test]
    fn init_policy_display_deny() {
        assert_eq!(InitPolicy::Deny.to_string(), "deny");
    }

    #[test]
    fn init_policy_display_dry_run() {
        assert_eq!(InitPolicy::DryRun.to_string(), "dry-run");
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn serde_provider_requirement_roundtrip() {
        let p = ProviderRequirement {
            name: "aws".into(),
            source: "hashicorp/aws".into(),
            version_constraint: Some("~> 5.0".into()),
            required_version: Some(">= 1.5".into()),
        };
        let json = serde_json::to_value(&p).unwrap();
        let p2: ProviderRequirement = serde_json::from_value(json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn serde_module_source_registry_roundtrip() {
        let src = ModuleSource::Registry {
            hostname: "registry.terraform.io".into(),
            namespace: "hashicorp".into(),
            name: "consul".into(),
            provider: "aws".into(),
        };
        let json = serde_json::to_value(&src).unwrap();
        let src2: ModuleSource = serde_json::from_value(json).unwrap();
        assert_eq!(src, src2);
    }

    #[test]
    fn serde_module_source_git_roundtrip() {
        let src = ModuleSource::Git {
            url: "https://example.com/mod.git".into(),
            ref_spec: Some("v1.0".into()),
        };
        let json = serde_json::to_value(&src).unwrap();
        let src2: ModuleSource = serde_json::from_value(json).unwrap();
        assert_eq!(src, src2);
    }

    #[test]
    fn serde_module_source_git_no_ref_roundtrip() {
        let src = ModuleSource::Git {
            url: "https://example.com/mod.git".into(),
            ref_spec: None,
        };
        let json = serde_json::to_value(&src).unwrap();
        let src2: ModuleSource = serde_json::from_value(json).unwrap();
        assert_eq!(src, src2);
    }

    #[test]
    fn serde_module_source_local_roundtrip() {
        let src = ModuleSource::Local {
            path: "./modules/net".into(),
        };
        let json = serde_json::to_value(&src).unwrap();
        let src2: ModuleSource = serde_json::from_value(json).unwrap();
        assert_eq!(src, src2);
    }

    #[test]
    fn serde_module_source_http_roundtrip() {
        let src = ModuleSource::Http {
            url: "https://example.com/mod.zip".into(),
        };
        let json = serde_json::to_value(&src).unwrap();
        let src2: ModuleSource = serde_json::from_value(json).unwrap();
        assert_eq!(src, src2);
    }

    #[test]
    fn serde_module_entry_roundtrip() {
        let e = ModuleEntry {
            key: "network".into(),
            source: ModuleSource::Registry {
                hostname: "registry.terraform.io".into(),
                namespace: "hashicorp".into(),
                name: "vpc".into(),
                provider: "aws".into(),
            },
            version: Some("3.0.0".into()),
            dir: None,
        };
        let json = serde_json::to_value(&e).unwrap();
        let e2: ModuleEntry = serde_json::from_value(json).unwrap();
        assert_eq!(e, e2);
    }

    #[test]
    fn serde_module_entry_with_dir_roundtrip() {
        let e = ModuleEntry {
            key: "sub".into(),
            source: ModuleSource::Git {
                url: "https://example.com/repo.git".into(),
                ref_spec: Some("main".into()),
            },
            version: None,
            dir: Some("subdir".into()),
        };
        let json = serde_json::to_value(&e).unwrap();
        let e2: ModuleEntry = serde_json::from_value(json).unwrap();
        assert_eq!(e, e2);
    }

    #[test]
    fn serde_root_module_roundtrip() {
        let r = RootModule {
            path: "/infra".into(),
            backend: Some("s3".into()),
        };
        let json = serde_json::to_value(&r).unwrap();
        let r2: RootModule = serde_json::from_value(json).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn serde_root_module_no_backend_roundtrip() {
        let r = RootModule {
            path: ".".into(),
            backend: None,
        };
        let json = serde_json::to_value(&r).unwrap();
        let r2: RootModule = serde_json::from_value(json).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn serde_module_graph_roundtrip() {
        let g = ModuleGraph {
            root_module: RootModule {
                path: ".".into(),
                backend: Some("remote".into()),
            },
            modules: vec![
                ModuleEntry {
                    key: "vpc".into(),
                    source: ModuleSource::Registry {
                        hostname: "registry.terraform.io".into(),
                        namespace: "hashicorp".into(),
                        name: "vpc".into(),
                        provider: "aws".into(),
                    },
                    version: Some("3.0.0".into()),
                    dir: None,
                },
                ModuleEntry {
                    key: "local_mod".into(),
                    source: ModuleSource::Local {
                        path: "./modules/local".into(),
                    },
                    version: None,
                    dir: None,
                },
            ],
            providers: vec![ProviderRequirement {
                name: "aws".into(),
                source: "hashicorp/aws".into(),
                version_constraint: Some("~> 5.0".into()),
                required_version: None,
            }],
        };
        let json = serde_json::to_value(&g).unwrap();
        let g2: ModuleGraph = serde_json::from_value(json).unwrap();
        assert_eq!(g, g2);
    }

    #[test]
    fn serde_module_graph_summary_roundtrip() {
        let s = ModuleGraphSummary {
            module_count: 5,
            provider_count: 2,
            has_remote_modules: true,
            has_local_modules: true,
            registry_modules: 3,
            git_modules: 1,
        };
        let json = serde_json::to_value(&s).unwrap();
        let s2: ModuleGraphSummary = serde_json::from_value(json).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn serde_init_policy_roundtrip_allow() {
        let p = InitPolicy::AllowDownload;
        let json = serde_json::to_value(p).unwrap();
        let p2: InitPolicy = serde_json::from_value(json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn serde_init_policy_roundtrip_deny() {
        let p = InitPolicy::Deny;
        let json = serde_json::to_value(p).unwrap();
        let p2: InitPolicy = serde_json::from_value(json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn serde_init_policy_roundtrip_dry_run() {
        let p = InitPolicy::DryRun;
        let json = serde_json::to_value(p).unwrap();
        let p2: InitPolicy = serde_json::from_value(json).unwrap();
        assert_eq!(p, p2);
    }

    // -----------------------------------------------------------------------
    // Clone trait tests
    // -----------------------------------------------------------------------

    #[test]
    fn provider_requirement_clone() {
        let p = ProviderRequirement {
            name: "aws".into(),
            source: "hashicorp/aws".into(),
            version_constraint: Some("~> 5.0".into()),
            required_version: None,
        };
        let cloned = p.clone();
        drop(p);
        assert_eq!(cloned.name, "aws");
    }

    #[test]
    fn module_source_clone_registry() {
        let src = ModuleSource::Registry {
            hostname: "r".into(),
            namespace: "n".into(),
            name: "m".into(),
            provider: "p".into(),
        };
        let cloned = src.clone();
        drop(src);
        assert_eq!(cloned.source_type(), "registry");
    }

    #[test]
    fn module_source_clone_git() {
        let src = ModuleSource::Git {
            url: "u".into(),
            ref_spec: Some("v1".into()),
        };
        let cloned = src.clone();
        drop(src);
        assert_eq!(cloned.source_type(), "git");
    }

    #[test]
    fn module_entry_clone() {
        let e = ModuleEntry {
            key: "k".into(),
            source: ModuleSource::Local { path: "./m".into() },
            version: None,
            dir: None,
        };
        let cloned = e.clone();
        drop(e);
        assert_eq!(cloned.key, "k");
    }

    #[test]
    fn root_module_clone() {
        let r = RootModule {
            path: ".".into(),
            backend: Some("s3".into()),
        };
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.path, ".");
        assert_eq!(cloned.backend, Some("s3".into()));
    }

    #[test]
    fn module_graph_clone() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let cloned = g.clone();
        drop(g);
        assert_eq!(cloned.modules.len(), 4);
    }

    #[test]
    fn module_graph_summary_clone() {
        let s = ModuleGraphSummary {
            module_count: 1,
            provider_count: 1,
            has_remote_modules: true,
            has_local_modules: false,
            registry_modules: 1,
            git_modules: 0,
        };
        let cloned = s.clone();
        assert_eq!(s.module_count, 1);
        assert_eq!(cloned.module_count, 1);
    }

    #[test]
    fn init_policy_clone() {
        let p = InitPolicy::DryRun;
        let cloned = p;
        assert_eq!(cloned, InitPolicy::DryRun);
    }

    // -----------------------------------------------------------------------
    // Debug trait tests
    // -----------------------------------------------------------------------

    #[test]
    fn provider_requirement_debug() {
        let p = ProviderRequirement {
            name: "aws".into(),
            source: "hashicorp/aws".into(),
            version_constraint: None,
            required_version: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("ProviderRequirement"));
        assert!(dbg.contains("aws"));
    }

    #[test]
    fn module_source_debug_registry() {
        let src = ModuleSource::Registry {
            hostname: "r".into(),
            namespace: "n".into(),
            name: "m".into(),
            provider: "p".into(),
        };
        let dbg = format!("{src:?}");
        assert!(dbg.contains("Registry"));
    }

    #[test]
    fn module_source_debug_git() {
        let src = ModuleSource::Git {
            url: "u".into(),
            ref_spec: None,
        };
        let dbg = format!("{src:?}");
        assert!(dbg.contains("Git"));
    }

    #[test]
    fn module_entry_debug() {
        let e = ModuleEntry {
            key: "k".into(),
            source: ModuleSource::Local { path: ".".into() },
            version: None,
            dir: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ModuleEntry"));
    }

    #[test]
    fn root_module_debug() {
        let r = RootModule {
            path: ".".into(),
            backend: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("RootModule"));
    }

    #[test]
    fn module_graph_debug() {
        let g = ModuleGraph {
            root_module: RootModule {
                path: ".".into(),
                backend: None,
            },
            modules: vec![],
            providers: vec![],
        };
        let dbg = format!("{g:?}");
        assert!(dbg.contains("ModuleGraph"));
    }

    #[test]
    fn init_policy_debug() {
        let dbg = format!("{:?}", InitPolicy::Deny);
        assert!(dbg.contains("Deny"));
    }

    // -----------------------------------------------------------------------
    // Multiple modules of different source types
    // -----------------------------------------------------------------------

    #[test]
    fn graph_with_many_registries() {
        let j = json!({
            "root": { "path": "." },
            "modules": [
                { "key": "vpc", "source": "hashicorp/vpc/aws" },
                { "key": "ecs", "source": "hashicorp/ecs/aws" },
                { "key": "rds", "source": "hashicorp/rds/aws" },
            ]
        });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert_eq!(g.modules_by_source_type("registry").len(), 3);
        let s = g.summary();
        assert_eq!(s.registry_modules, 3);
        assert!(!s.has_local_modules);
    }

    #[test]
    fn graph_with_many_locals() {
        let j = json!({
            "root": { "path": "." },
            "modules": [
                { "key": "a", "source": "./a" },
                { "key": "b", "source": "../b" },
                { "key": "c", "source": "./c/d" },
            ]
        });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert_eq!(g.modules_by_source_type("local").len(), 3);
        assert!(!g.summary().has_remote_modules);
    }

    #[test]
    fn graph_with_many_git_modules() {
        let j = json!({
            "root": { "path": "." },
            "modules": [
                { "key": "a", "source": "git::https://ex.com/a.git" },
                { "key": "b", "source": "git::https://ex.com/b.git?ref=main" },
            ]
        });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert_eq!(g.modules_by_source_type("git").len(), 2);
        assert_eq!(g.summary().git_modules, 2);
    }

    // -----------------------------------------------------------------------
    // Edge case: unusual source formats
    // -----------------------------------------------------------------------

    #[test]
    fn parse_registry_with_many_segments() {
        // 5+ segments: first 4 are used, rest ignored
        let src = ModuleSource::parse("host.com/ns/name/provider/extra");
        match src {
            ModuleSource::Registry {
                hostname,
                namespace,
                name,
                provider,
            } => {
                assert_eq!(hostname, "host.com");
                assert_eq!(namespace, "ns");
                assert_eq!(name, "name");
                assert_eq!(provider, "provider");
            }
            other => panic!("expected Registry, got {other:?}"),
        }
    }

    #[test]
    fn parse_git_with_subdir() {
        let src = ModuleSource::parse("git::https://example.com/repo.git//subdir?ref=v1");
        match src {
            ModuleSource::Git { url, ref_spec } => {
                assert!(url.contains("//subdir"));
                assert_eq!(ref_spec, Some("v1".to_string()));
            }
            other => panic!("expected Git, got {other:?}"),
        }
    }

    #[test]
    fn parse_github_https_with_ref() {
        let src = ModuleSource::parse("https://github.com/org/repo?ref=v2.0");
        match src {
            ModuleSource::Git { ref_spec, .. } => {
                assert_eq!(ref_spec, Some("v2.0".to_string()));
            }
            other => panic!("expected Git, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // PartialEq tests
    // -----------------------------------------------------------------------

    #[test]
    fn provider_requirement_equality() {
        let a = ProviderRequirement {
            name: "aws".into(),
            source: "hashicorp/aws".into(),
            version_constraint: Some("~> 5.0".into()),
            required_version: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn provider_requirement_inequality() {
        let a = ProviderRequirement {
            name: "aws".into(),
            source: "hashicorp/aws".into(),
            version_constraint: Some("~> 5.0".into()),
            required_version: None,
        };
        let b = ProviderRequirement {
            name: "gcp".into(),
            source: "hashicorp/google".into(),
            version_constraint: None,
            required_version: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn module_source_equality() {
        let a = ModuleSource::Local { path: "./a".into() };
        let b = ModuleSource::Local { path: "./a".into() };
        assert_eq!(a, b);
    }

    #[test]
    fn module_source_inequality_different_variants() {
        let a = ModuleSource::Local { path: "./a".into() };
        let b = ModuleSource::Git {
            url: "./a".into(),
            ref_spec: None,
        };
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // Init policy integration with summary
    // -----------------------------------------------------------------------

    #[test]
    fn init_policy_with_mixed_graph() {
        let g = ModuleGraph::from_json(&sample_json()).unwrap();
        let s = g.summary();
        assert!(
            InitPolicy::AllowDownload
                .evaluate(s.has_remote_modules)
                .is_ok()
        );
        assert!(InitPolicy::Deny.evaluate(s.has_remote_modules).is_err());
        assert!(InitPolicy::DryRun.evaluate(s.has_remote_modules).is_err());
    }

    #[test]
    fn init_policy_with_local_only_graph() {
        let j = json!({
            "root": { "path": "." },
            "modules": [
                { "key": "a", "source": "./a" },
            ]
        });
        let g = ModuleGraph::from_json(&j).unwrap();
        let s = g.summary();
        assert!(
            InitPolicy::AllowDownload
                .evaluate(s.has_remote_modules)
                .is_ok()
        );
        assert!(InitPolicy::Deny.evaluate(s.has_remote_modules).is_ok());
        assert!(InitPolicy::DryRun.evaluate(s.has_remote_modules).is_ok());
    }

    // -----------------------------------------------------------------------
    // Extra edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn from_json_provider_with_all_fields() {
        let j = json!({
            "root": { "path": "." },
            "providers": [{
                "name": "azurerm",
                "source": "hashicorp/azurerm",
                "version_constraint": ">= 3.0, < 4.0",
                "required_version": ">= 1.3.0"
            }]
        });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert_eq!(g.providers[0].name, "azurerm");
        assert_eq!(g.providers[0].source, "hashicorp/azurerm");
        assert_eq!(
            g.providers[0].version_constraint,
            Some(">= 3.0, < 4.0".into())
        );
        assert_eq!(g.providers[0].required_version, Some(">= 1.3.0".into()));
    }

    #[test]
    fn from_json_multiple_providers() {
        let j = json!({
            "root": { "path": "." },
            "providers": [
                { "name": "aws", "source": "hashicorp/aws" },
                { "name": "azurerm", "source": "hashicorp/azurerm" },
                { "name": "google", "source": "hashicorp/google" },
            ]
        });
        let g = ModuleGraph::from_json(&j).unwrap();
        assert_eq!(g.providers.len(), 3);
    }

    #[test]
    fn module_entry_display_http() {
        let e = ModuleEntry {
            key: "archive".into(),
            source: ModuleSource::Http {
                url: "https://example.com/mod.zip".into(),
            },
            version: None,
            dir: None,
        };
        let s = e.to_string();
        assert!(s.contains("module.archive"));
        assert!(s.contains("https://example.com/mod.zip"));
    }

    #[test]
    fn module_entry_display_git() {
        let e = ModuleEntry {
            key: "gitmod".into(),
            source: ModuleSource::Git {
                url: "https://github.com/org/repo".into(),
                ref_spec: Some("main".into()),
            },
            version: None,
            dir: None,
        };
        let s = e.to_string();
        assert!(s.contains("module.gitmod"));
        assert!(s.contains("git::"));
    }
}
