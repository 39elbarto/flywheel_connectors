//! Read-only RCH dated-toolchain and preflight-cache coherency reporting.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RCH_TOOLCHAIN_DOCTOR_SCHEMA: &str = "fcp.rch-toolchain-doctor.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchToolchainDoctorReport {
    pub schema_version: &'static str,
    pub generated_at: DateTime<Utc>,
    pub mutation_attempted: bool,
    pub git_revision: Option<String>,
    pub repo_toolchain: ToolchainRequirement,
    pub diagnose: DiagnoseEvidence,
    pub workers: Vec<WorkerToolchainReport>,
    pub overall_status: ToolchainDoctorStatus,
    pub reason_codes: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub direct_ssh_accepted_as_proof: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolchainDoctorStatus {
    Healthy,
    Warning,
    Blocked,
}

impl ToolchainDoctorStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolchainRequirement {
    pub source_path: Option<PathBuf>,
    pub channel: String,
    pub components: Vec<String>,
    pub is_dated_nightly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnoseEvidence {
    pub source_path: Option<PathBuf>,
    pub parsed: bool,
    pub required_toolchain: Option<String>,
    pub missing_toolchains: Vec<String>,
    pub worker_user: Option<String>,
    pub worker_home: Option<String>,
    pub reason: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerToolchainReport {
    pub source_path: Option<PathBuf>,
    pub parsed: bool,
    pub worker_id_hash: Option<String>,
    pub direct_observation_class: ToolchainObservationClass,
    pub required_toolchain: String,
    pub user: Option<String>,
    pub home: Option<String>,
    pub installed_toolchains: Vec<String>,
    pub rustup_run_success: Option<bool>,
    pub rustc_version: Option<String>,
    pub reason: String,
    pub recommended_next_command: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolchainObservationClass {
    ToolchainInstalled,
    WorkerToolchainMissing,
    DatedToolchainMissing,
    WorkerUserEnvMismatch,
    PreflightCacheStaleOrWrongEnv,
    ToolchainEvidenceInconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RchToolchainDoctorConfig {
    pub now: DateTime<Utc>,
    pub git_revision: Option<String>,
    pub required_toolchain_override: Option<String>,
}

impl RchToolchainDoctorConfig {
    #[must_use]
    pub const fn default_with_now(now: DateTime<Utc>) -> Self {
        Self {
            now,
            git_revision: None,
            required_toolchain_override: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerObservationSource {
    pub source_path: Option<PathBuf>,
    pub value: Option<Value>,
    pub error: Option<String>,
}

#[must_use]
pub fn load_toolchain_requirement(path: &Path) -> ToolchainRequirement {
    let raw = fs::read_to_string(path).unwrap_or_default();
    parse_toolchain_requirement(Some(path.to_path_buf()), &raw)
}

#[must_use]
pub fn parse_toolchain_requirement(path: Option<PathBuf>, raw: &str) -> ToolchainRequirement {
    let value = raw
        .parse::<toml::Value>()
        .unwrap_or_else(|_| toml::Value::Table(toml::Table::new()));
    let toolchain = value.get("toolchain");
    let channel = toolchain
        .and_then(|toolchain| toolchain.get("channel"))
        .and_then(toml::Value::as_str)
        .unwrap_or("nightly")
        .to_string();
    let components = toolchain
        .and_then(|toolchain| toolchain.get("components"))
        .and_then(toml::Value::as_array)
        .map_or_else(Vec::new, |components| {
            components
                .iter()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        });

    ToolchainRequirement {
        source_path: path,
        is_dated_nightly: is_dated_nightly(&channel),
        channel,
        components,
    }
}

#[must_use]
pub fn load_diagnose_evidence(path: Option<&Path>, summary_lines: &[String]) -> DiagnoseEvidence {
    let mut docs = Vec::new();
    let mut errors = Vec::new();
    if let Some(path) = path {
        match fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<Value>(&raw) {
                Ok(value) => docs.push(value),
                Err(error) => errors.push(format!("diagnose JSON did not parse: {error}")),
            },
            Err(error) => errors.push(format!("could not read diagnose evidence: {error}")),
        }
    }
    parse_diagnose_evidence(path.map(Path::to_path_buf), &docs, summary_lines, &errors)
}

#[must_use]
pub fn parse_diagnose_evidence(
    path: Option<PathBuf>,
    docs: &[Value],
    summary_lines: &[String],
    errors: &[String],
) -> DiagnoseEvidence {
    let mut raw_fragments = summary_lines.to_vec();
    raw_fragments.extend(docs.iter().map(Value::to_string));
    let raw = raw_fragments.join("\n");
    let lower_raw = raw.to_ascii_lowercase();
    let mut missing_toolchains = toolchain_tokens(&raw);
    if !(lower_raw.contains("missing") || lower_raw.contains("not installed")) {
        missing_toolchains.clear();
    }
    missing_toolchains.sort();
    missing_toolchains.dedup();

    let worker_user = docs
        .iter()
        .find_map(|value| string_field(value, &["worker_user", "user", "service_user"]));
    let worker_home = docs
        .iter()
        .find_map(|value| string_field(value, &["worker_home", "home", "rustup_home"]));

    DiagnoseEvidence {
        source_path: path,
        parsed: errors.is_empty(),
        required_toolchain: missing_toolchains.first().cloned(),
        missing_toolchains,
        worker_user,
        worker_home,
        reason: truncate_text(&raw),
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

#[must_use]
pub fn load_worker_observation(path: &Path) -> WorkerObservationSource {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(value) => WorkerObservationSource {
                source_path: Some(path.to_path_buf()),
                value: Some(value),
                error: None,
            },
            Err(error) => WorkerObservationSource {
                source_path: Some(path.to_path_buf()),
                value: None,
                error: Some(format!("worker observation JSON did not parse: {error}")),
            },
        },
        Err(error) => WorkerObservationSource {
            source_path: Some(path.to_path_buf()),
            value: None,
            error: Some(format!("could not read worker observation: {error}")),
        },
    }
}

#[must_use]
pub fn build_rch_toolchain_doctor_report(
    repo_toolchain: ToolchainRequirement,
    diagnose: DiagnoseEvidence,
    worker_sources: &[WorkerObservationSource],
    config: &RchToolchainDoctorConfig,
) -> RchToolchainDoctorReport {
    let required_toolchain = config
        .required_toolchain_override
        .clone()
        .or_else(|| diagnose.required_toolchain.clone())
        .unwrap_or_else(|| repo_toolchain.channel.clone());
    let workers = worker_sources
        .iter()
        .map(|source| classify_worker_source(source, &diagnose, &required_toolchain))
        .collect::<Vec<_>>();
    let mut reason_codes = collect_reason_codes(&diagnose, &workers);
    if repo_toolchain.channel == "nightly" && is_dated_nightly(&required_toolchain) {
        reason_codes.push("generic_nightly_vs_dated_nightly_drift".to_string());
    }
    reason_codes.sort();
    reason_codes.dedup();
    let overall_status = overall_status(&diagnose, &workers, &reason_codes);
    let recommended_actions =
        recommended_actions(overall_status, &reason_codes, &required_toolchain);

    RchToolchainDoctorReport {
        schema_version: RCH_TOOLCHAIN_DOCTOR_SCHEMA,
        generated_at: config.now,
        mutation_attempted: false,
        git_revision: config.git_revision.clone(),
        repo_toolchain,
        diagnose,
        workers,
        overall_status,
        reason_codes,
        recommended_actions,
        direct_ssh_accepted_as_proof: false,
    }
}

#[must_use]
pub fn render_table(report: &RchToolchainDoctorReport) -> String {
    let mut out = String::new();
    out.push_str(
        "overall_status\tmutation_attempted\trepo_toolchain\tdiagnose_required\tworkers\treasons\n",
    );
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            report.overall_status.as_str(),
            report.mutation_attempted,
            report.repo_toolchain.channel,
            report.diagnose.required_toolchain.as_deref().unwrap_or("-"),
            report.workers.len(),
            report.reason_codes.join(",")
        ),
    );
    out
}

fn classify_worker_source(
    source: &WorkerObservationSource,
    diagnose: &DiagnoseEvidence,
    required_toolchain: &str,
) -> WorkerToolchainReport {
    let Some(value) = &source.value else {
        return inconclusive_report(source, required_toolchain, source.error.clone());
    };

    let worker_id = string_field(value, &["worker_id", "id", "worker"]);
    let user = string_field(value, &["user", "worker_user", "service_user"]);
    let home = string_field(value, &["home", "worker_home", "rustup_home"]);
    let installed_toolchains = installed_toolchains(value);
    let rustup_run_success = bool_field(value, &["rustup_run_success", "rustc_success"]);
    let rustc_version = string_field(value, &["rustc_version", "rustup_run_rustc_version"]);
    let mismatch = diagnose
        .worker_user
        .as_ref()
        .zip(user.as_ref())
        .is_some_and(|(left, right)| left != right)
        || diagnose
            .worker_home
            .as_ref()
            .zip(home.as_ref())
            .is_some_and(|(left, right)| left != right);

    let direct_has_required = installed_toolchains
        .iter()
        .any(|toolchain| toolchain_matches(toolchain, required_toolchain))
        || rustup_run_success == Some(true);
    let has_generic_nightly = installed_toolchains
        .iter()
        .any(|toolchain| toolchain == "nightly" || toolchain.starts_with("nightly-"));
    let diagnose_missing_required = diagnose
        .missing_toolchains
        .iter()
        .any(|toolchain| toolchain_matches(toolchain, required_toolchain));

    let direct_observation_class = if mismatch {
        ToolchainObservationClass::WorkerUserEnvMismatch
    } else if diagnose_missing_required && direct_has_required {
        ToolchainObservationClass::PreflightCacheStaleOrWrongEnv
    } else if direct_has_required {
        ToolchainObservationClass::ToolchainInstalled
    } else if is_dated_nightly(required_toolchain) && has_generic_nightly {
        ToolchainObservationClass::DatedToolchainMissing
    } else if !installed_toolchains.is_empty() || rustup_run_success == Some(false) {
        ToolchainObservationClass::WorkerToolchainMissing
    } else {
        ToolchainObservationClass::ToolchainEvidenceInconclusive
    };

    WorkerToolchainReport {
        source_path: source.source_path.clone(),
        parsed: true,
        worker_id_hash: worker_id.as_deref().map(hash_worker_id),
        direct_observation_class,
        required_toolchain: required_toolchain.to_string(),
        user,
        home,
        installed_toolchains,
        rustup_run_success,
        rustc_version,
        reason: observation_reason(direct_observation_class),
        recommended_next_command: worker_next_command(direct_observation_class, required_toolchain),
        error: None,
    }
}

fn inconclusive_report(
    source: &WorkerObservationSource,
    required_toolchain: &str,
    error: Option<String>,
) -> WorkerToolchainReport {
    WorkerToolchainReport {
        source_path: source.source_path.clone(),
        parsed: false,
        worker_id_hash: None,
        direct_observation_class: ToolchainObservationClass::ToolchainEvidenceInconclusive,
        required_toolchain: required_toolchain.to_string(),
        user: None,
        home: None,
        installed_toolchains: Vec::new(),
        rustup_run_success: None,
        rustc_version: None,
        reason: "worker observation was unavailable or malformed".to_string(),
        recommended_next_command: "recapture worker evidence with redaction-safe rustup list and rustup run output before repairing".to_string(),
        error,
    }
}

fn collect_reason_codes(
    diagnose: &DiagnoseEvidence,
    workers: &[WorkerToolchainReport],
) -> Vec<String> {
    let mut codes = Vec::new();
    if !diagnose.parsed {
        codes.push("diagnose_evidence_inconclusive".to_string());
    }
    if !diagnose.missing_toolchains.is_empty() {
        codes.push("diagnose_reports_missing_toolchain".to_string());
    }
    for worker in workers {
        codes.push(match worker.direct_observation_class {
            ToolchainObservationClass::ToolchainInstalled => "toolchain_installed".to_string(),
            ToolchainObservationClass::WorkerToolchainMissing => {
                "worker_toolchain_missing".to_string()
            }
            ToolchainObservationClass::DatedToolchainMissing => {
                "dated_toolchain_missing".to_string()
            }
            ToolchainObservationClass::WorkerUserEnvMismatch => {
                "worker_user_env_mismatch".to_string()
            }
            ToolchainObservationClass::PreflightCacheStaleOrWrongEnv => {
                "preflight_cache_stale_or_wrong_env".to_string()
            }
            ToolchainObservationClass::ToolchainEvidenceInconclusive => {
                "toolchain_evidence_inconclusive".to_string()
            }
        });
    }
    codes
}

fn overall_status(
    diagnose: &DiagnoseEvidence,
    workers: &[WorkerToolchainReport],
    reason_codes: &[String],
) -> ToolchainDoctorStatus {
    if !diagnose.parsed
        || workers.iter().any(|worker| {
            worker.direct_observation_class
                == ToolchainObservationClass::ToolchainEvidenceInconclusive
        })
    {
        return ToolchainDoctorStatus::Blocked;
    }
    if reason_codes.iter().any(|code| {
        matches!(
            code.as_str(),
            "worker_toolchain_missing"
                | "dated_toolchain_missing"
                | "worker_user_env_mismatch"
                | "preflight_cache_stale_or_wrong_env"
        )
    }) {
        return ToolchainDoctorStatus::Blocked;
    }
    if !diagnose.missing_toolchains.is_empty() || workers.is_empty() {
        return ToolchainDoctorStatus::Warning;
    }
    ToolchainDoctorStatus::Healthy
}

fn recommended_actions(
    status: ToolchainDoctorStatus,
    reason_codes: &[String],
    required_toolchain: &str,
) -> Vec<String> {
    let mut actions = Vec::new();
    match status {
        ToolchainDoctorStatus::Healthy => {
            actions.push(
                "toolchain observations agree; retry rch diagnose before Cargo proof".to_string(),
            );
        }
        ToolchainDoctorStatus::Warning | ToolchainDoctorStatus::Blocked => {
            actions
                .push("treat this as proof-infra diagnosis, not accepted Cargo proof".to_string());
            actions.push(
                "do not run rustup, restart rch, reload daemons, or repair services automatically"
                    .to_string(),
            );
        }
    }
    if reason_codes
        .iter()
        .any(|code| code == "preflight_cache_stale_or_wrong_env")
    {
        actions.push("ask the rch owner to invalidate or refresh preflight cache after verifying the worker service user".to_string());
    }
    if reason_codes
        .iter()
        .any(|code| code == "worker_user_env_mismatch")
    {
        actions.push("compare the rch service account HOME and rustup home with the direct SSH account before installing anything".to_string());
    }
    if reason_codes
        .iter()
        .any(|code| code == "worker_toolchain_missing" || code == "dated_toolchain_missing")
    {
        actions.push(format!(
            "with human approval, install `{required_toolchain}` plus rustfmt and clippy on the affected worker account"
        ));
    }
    actions
}

fn observation_reason(classification: ToolchainObservationClass) -> String {
    match classification {
        ToolchainObservationClass::ToolchainInstalled => {
            "direct observation reports the required toolchain installed".to_string()
        }
        ToolchainObservationClass::WorkerToolchainMissing => {
            "direct observation does not include the required toolchain".to_string()
        }
        ToolchainObservationClass::DatedToolchainMissing => {
            "worker has generic nightly evidence but not the dated nightly required by preflight".to_string()
        }
        ToolchainObservationClass::WorkerUserEnvMismatch => {
            "direct evidence appears to come from a different user or rustup HOME than rch preflight".to_string()
        }
        ToolchainObservationClass::PreflightCacheStaleOrWrongEnv => {
            "rch preflight reports missing toolchain while direct observation reports it installed".to_string()
        }
        ToolchainObservationClass::ToolchainEvidenceInconclusive => {
            "worker observation could not prove toolchain state".to_string()
        }
    }
}

fn worker_next_command(
    classification: ToolchainObservationClass,
    required_toolchain: &str,
) -> String {
    match classification {
        ToolchainObservationClass::PreflightCacheStaleOrWrongEnv => {
            "ask a human to verify rch preflight cache/service-user state; rerun `rch diagnose --dry-run` after approval".to_string()
        }
        ToolchainObservationClass::WorkerToolchainMissing
        | ToolchainObservationClass::DatedToolchainMissing => format!(
            "after explicit human approval: `rustup toolchain install {required_toolchain} --component rustfmt --component clippy`"
        ),
        ToolchainObservationClass::WorkerUserEnvMismatch => {
            "recapture rustup evidence as the rch service user before installing toolchains".to_string()
        }
        ToolchainObservationClass::ToolchainEvidenceInconclusive => {
            "recapture redaction-safe worker observation JSON before taking repair action".to_string()
        }
        ToolchainObservationClass::ToolchainInstalled => {
            "rerun `rch diagnose --dry-run` and keep direct SSH evidence out of accepted Cargo proof".to_string()
        }
    }
}

fn installed_toolchains(value: &Value) -> Vec<String> {
    let mut toolchains = BTreeSet::new();
    collect_toolchain_values(value, &mut toolchains);
    toolchains.into_iter().collect()
}

fn collect_toolchain_values(value: &Value, toolchains: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            toolchains.extend(toolchain_tokens(text));
        }
        Value::Array(values) => {
            for value in values {
                collect_toolchain_values(value, toolchains);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                if key.contains("toolchain") || key.contains("rustup") || key.contains("rustc") {
                    collect_toolchain_values(value, toolchains);
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn toolchain_tokens(raw: &str) -> Vec<String> {
    raw.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    })
    .filter(|token| {
        token == &"nightly"
            || token.starts_with("nightly-")
            || token.starts_with("stable-")
            || token.starts_with("beta-")
    })
    .map(ToOwned::to_owned)
    .collect()
}

fn string_field(value: &Value, names: &[&str]) -> Option<String> {
    let Value::Object(map) = value else {
        return None;
    };
    for name in names {
        if let Some(text) = map.get(*name).and_then(Value::as_str) {
            return Some(text.to_string());
        }
    }
    None
}

fn bool_field(value: &Value, names: &[&str]) -> Option<bool> {
    let Value::Object(map) = value else {
        return None;
    };
    for name in names {
        if let Some(flag) = map.get(*name).and_then(Value::as_bool) {
            return Some(flag);
        }
    }
    None
}

fn toolchain_matches(observed: &str, required: &str) -> bool {
    observed == required || observed.starts_with(&format!("{required}-"))
}

fn is_dated_nightly(toolchain: &str) -> bool {
    let Some(date) = toolchain.strip_prefix("nightly-") else {
        return false;
    };
    let mut parts = date.splitn(4, '-');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(year), Some(month), Some(day))
            if year.len() == 4
                && month.len() == 2
                && day.len() == 2
                && year.chars().all(|ch| ch.is_ascii_digit())
                && month.chars().all(|ch| ch.is_ascii_digit())
                && day.chars().all(|ch| ch.is_ascii_digit())
    )
}

fn hash_worker_id(worker_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(worker_id.as_bytes());
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn truncate_text(raw: &str) -> String {
    const MAX_CHARS: usize = 320;
    let redacted = redact_sensitive(raw);
    if redacted.chars().count() <= MAX_CHARS {
        return redacted;
    }
    let mut truncated = redacted.chars().take(MAX_CHARS).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn redact_sensitive(raw: &str) -> String {
    let replacements = BTreeMap::from([
        ("token", "<redacted-key>"),
        ("secret", "<redacted-key>"),
        ("password", "<redacted-key>"),
        ("bearer", "<redacted-key>"),
    ]);
    raw.split_whitespace()
        .map(|token| {
            let lower = token.to_ascii_lowercase();
            replacements
                .iter()
                .find_map(|(needle, replacement)| lower.contains(needle).then_some(*replacement))
                .unwrap_or(token)
        })
        .collect::<Vec<_>>()
        .join(" ")
}
