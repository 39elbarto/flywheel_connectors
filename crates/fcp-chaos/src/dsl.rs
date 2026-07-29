//! Declarative chaos scenario TOML parsing.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

/// A parsed chaos scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaosScenario {
    /// Stable scenario name used in logs and evidence.
    pub name: String,
    /// Maximum number of synthetic units this scenario may affect.
    pub blast_radius: u32,
    /// Recovery objective for the scenario.
    pub recovery_objective_secs: u64,
    /// Rollback steps executed on completion and abort.
    pub rollback_steps: Vec<RollbackStep>,
}

/// One rollback action declared by a scenario.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackStep {
    /// Step name, stable for logs.
    pub name: String,
    /// Operator-facing action identifier.
    pub action: String,
    /// Optional target this rollback action applies to.
    #[serde(default)]
    pub target: Option<String>,
    /// Optional string parameters for the rollback action.
    #[serde(default)]
    pub args: BTreeMap<String, String>,
}

/// Parser errors for scenario TOML.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DslError {
    /// Required field was absent.
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    /// A field was present but invalid.
    #[error("invalid value for `{field}`: {reason}")]
    InvalidValue {
        /// Field name.
        field: &'static str,
        /// Human-readable reason.
        reason: String,
    },
    /// TOML syntax or type error.
    #[error("invalid TOML: {0}")]
    InvalidToml(String),
    /// File read failed.
    #[error("failed to read scenario file `{path}`: {error}")]
    Read {
        /// Path that failed.
        path: String,
        /// IO error text.
        error: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScenario {
    name: Option<String>,
    blast_radius: Option<i64>,
    recovery_objective_secs: Option<i64>,
    #[serde(default)]
    rollback_steps: Vec<RollbackStep>,
}

impl ChaosScenario {
    /// Parse a chaos scenario from TOML.
    ///
    /// # Errors
    ///
    /// Returns [`DslError`] when TOML is malformed, required fields are
    /// missing, numeric fields are outside their accepted range, or no rollback
    /// step is declared.
    pub fn from_toml_str(input: &str) -> Result<Self, DslError> {
        let raw: RawScenario =
            toml::from_str(input).map_err(|error| DslError::InvalidToml(error.to_string()))?;
        let name = raw.name.ok_or(DslError::MissingField("name"))?;
        if name.trim().is_empty() {
            return Err(DslError::InvalidValue {
                field: "name",
                reason: "must not be empty".into(),
            });
        }

        let blast_radius = require_positive_u32(raw.blast_radius, "blast_radius")?;
        let recovery_objective_secs =
            require_positive_u64(raw.recovery_objective_secs, "recovery_objective_secs")?;
        if raw.rollback_steps.is_empty() {
            return Err(DslError::MissingField("rollback_steps"));
        }

        Ok(Self {
            name,
            blast_radius,
            recovery_objective_secs,
            rollback_steps: raw.rollback_steps,
        })
    }

    /// Parse a chaos scenario from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`DslError::Read`] if the file cannot be read, or another
    /// [`DslError`] if the content is not a valid scenario.
    pub fn from_path(path: &Path) -> Result<Self, DslError> {
        let input = std::fs::read_to_string(path).map_err(|error| DslError::Read {
            path: path.display().to_string(),
            error: error.to_string(),
        })?;
        Self::from_toml_str(&input)
    }
}

fn require_positive_u32(value: Option<i64>, field: &'static str) -> Result<u32, DslError> {
    let value = value.ok_or(DslError::MissingField(field))?;
    if value <= 0 {
        return Err(DslError::InvalidValue {
            field,
            reason: "must be positive".into(),
        });
    }
    u32::try_from(value).map_err(|_| DslError::InvalidValue {
        field,
        reason: "exceeds u32::MAX".into(),
    })
}

fn require_positive_u64(value: Option<i64>, field: &'static str) -> Result<u64, DslError> {
    let value = value.ok_or(DslError::MissingField(field))?;
    if value <= 0 {
        return Err(DslError::InvalidValue {
            field,
            reason: "must be positive".into(),
        });
    }
    u64::try_from(value).map_err(|_| DslError::InvalidValue {
        field,
        reason: "exceeds u64::MAX".into(),
    })
}
