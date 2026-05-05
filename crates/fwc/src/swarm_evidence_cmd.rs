//! Operator-facing swarm evidence exploration.
//!
//! This command intentionally reads replayable JSONL artifacts offline. It does
//! not contact live services or reinterpret adaptive decisions; it surfaces the
//! exact decision cards and report links already stored in the evidence bundle.

use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};

/// Arguments for `fwc swarm-evidence`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct SwarmEvidenceArgs {
    #[command(subcommand)]
    pub command: SwarmEvidenceCommand,
}

/// Swarm evidence subcommands.
#[derive(Subcommand, Debug, Clone, Serialize)]
pub enum SwarmEvidenceCommand {
    /// List and filter swarm decision cards from a JSONL evidence bundle.
    Explore(SwarmEvidenceExploreArgs),
    /// Render stored decision-card replay details without live services.
    Replay(SwarmEvidenceReplayArgs),
}

/// Common redaction-safe filters for decision cards.
#[derive(Args, Debug, Clone, Default, Serialize)]
pub struct SwarmEvidenceFilters {
    /// Match a zone string anywhere inside the decision-card record.
    #[arg(long)]
    pub zone: Option<String>,

    /// Match a connector string anywhere inside the decision-card record.
    #[arg(long)]
    pub connector: Option<String>,

    /// Match a principal string anywhere inside the decision-card record.
    #[arg(long)]
    pub principal: Option<String>,

    /// Match the card scenario id or any scenario string in the record.
    #[arg(long)]
    pub scenario: Option<String>,

    /// Match a correlation id string anywhere inside the decision-card record.
    #[arg(long = "correlation-id")]
    pub correlation_id: Option<String>,

    /// Match the selected action, for example `admit`, `delay`, or `fallback`.
    #[arg(long)]
    pub action: Option<String>,

    /// Match the fallback reason attached to the decision card.
    #[arg(long = "fallback-reason")]
    pub fallback_reason: Option<String>,

    /// Match the dominant loss-term name.
    #[arg(long = "dominant-loss-term")]
    pub dominant_loss_term: Option<String>,
}

/// Arguments for `fwc swarm-evidence explore`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct SwarmEvidenceExploreArgs {
    /// JSONL evidence bundle or log to inspect.
    pub file: PathBuf,

    #[command(flatten)]
    pub filters: SwarmEvidenceFilters,

    /// Maximum decision-card entries to return.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    /// Number of filtered entries to skip.
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
}

/// Arguments for `fwc swarm-evidence replay`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct SwarmEvidenceReplayArgs {
    /// JSONL evidence bundle or log to inspect.
    pub file: PathBuf,

    /// Restrict replay rendering to one or more decision-card ids.
    #[arg(long = "card-id")]
    pub card_ids: Vec<String>,

    #[command(flatten)]
    pub filters: SwarmEvidenceFilters,

    /// Maximum decision-card entries to return.
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

#[derive(Debug, Clone)]
struct JsonlRecord {
    line: usize,
    value: Value,
}

#[derive(Debug, Clone)]
struct DecisionCardEntry {
    line: usize,
    card_id: String,
    scenario_id: Option<String>,
    domain: Option<String>,
    subject: Option<String>,
    action: Option<String>,
    state: Option<String>,
    calibration: Option<String>,
    fallback_active: bool,
    fallback_action: Option<String>,
    fallback_reason: Option<String>,
    counterfactual_action: Option<String>,
    counterfactual_reason: Option<String>,
    dominant_loss_term: Option<Value>,
    evidence_handles: Vec<Value>,
    replayable_offline: bool,
    raw_record: Value,
}

/// Run a `fwc swarm-evidence` command and return a structured payload.
pub fn run(args: &SwarmEvidenceArgs) -> Result<Value> {
    match &args.command {
        SwarmEvidenceCommand::Explore(args) => explore(args),
        SwarmEvidenceCommand::Replay(args) => replay(args),
    }
}

fn explore(args: &SwarmEvidenceExploreArgs) -> Result<Value> {
    let records = load_jsonl_records(&args.file)?;
    let entries = filtered_entries(&records, &args.filters, &[])?;
    let total_filtered = entries.len();
    let page = entries
        .iter()
        .skip(args.offset)
        .take(args.limit)
        .map(entry_summary)
        .collect::<Vec<_>>();
    let reports = report_links(&records);

    let mut payload = json!({
        "status": "ok",
        "command": "swarm-evidence explore",
        "source": &args.file,
        "summary": bundle_summary(&records, total_filtered),
        "filters": serde_json::to_value(&args.filters)?,
        "pagination": {
            "offset": args.offset,
            "limit": args.limit,
            "returned": page.len(),
            "total_filtered": total_filtered,
            "has_more": args.offset.saturating_add(page.len()) < total_filtered,
        },
        "entries": page,
        "reports": reports,
        "message": format!(
            "Loaded {} swarm decision card(s) from `{}`.",
            total_filtered,
            args.file.display()
        ),
        "next_actions": [
            "Use `fwc swarm-evidence replay <file> --card-id <id>` to inspect exact stored decisions.",
            "Use `--format json` for structured decision-card records and evidence pointers.",
        ],
    });
    let toon = format_explore_toon(&payload);
    insert_toon(&mut payload, toon);
    Ok(payload)
}

fn replay(args: &SwarmEvidenceReplayArgs) -> Result<Value> {
    let records = load_jsonl_records(&args.file)?;
    let mut entries = filtered_entries(&records, &args.filters, &args.card_ids)?;
    entries.truncate(args.limit);
    let replays = entries.iter().map(replay_summary).collect::<Vec<_>>();

    let mut payload = json!({
        "status": "ok",
        "command": "swarm-evidence replay",
        "source": &args.file,
        "summary": bundle_summary(&records, entries.len()),
        "filters": serde_json::to_value(&args.filters)?,
        "card_ids": &args.card_ids,
        "entries": replays,
        "message": format!(
            "Rendered {} stored swarm decision card(s) from `{}`.",
            entries.len(),
            args.file.display()
        ),
        "replay_boundary": "Offline replay renders stored decision-card inputs, action, fallback, counterfactual, and evidence pointers; it does not call live services or recompute host state.",
    });
    let toon = format_replay_toon(&payload);
    insert_toon(&mut payload, toon);
    Ok(payload)
}

fn insert_toon(payload: &mut Value, toon: String) {
    if let Some(object) = payload.as_object_mut() {
        object.insert("toon".to_owned(), Value::String(toon));
    }
}

fn load_jsonl_records(path: &Path) -> Result<Vec<JsonlRecord>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open swarm evidence JSONL `{}`", path.display()))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.with_context(|| {
            format!(
                "failed to read line {line_number} from swarm evidence JSONL `{}`",
                path.display()
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(&line).with_context(|| {
            format!(
                "line {line_number} in `{}` is not valid JSON",
                path.display()
            )
        })?;
        records.push(JsonlRecord {
            line: line_number,
            value,
        });
    }

    Ok(records)
}

fn filtered_entries(
    records: &[JsonlRecord],
    filters: &SwarmEvidenceFilters,
    card_ids: &[String],
) -> Result<Vec<DecisionCardEntry>> {
    let mut entries = records
        .iter()
        .filter_map(decision_card_entry)
        .filter(|entry| card_ids.is_empty() || card_ids.iter().any(|id| id == &entry.card_id))
        .filter(|entry| matches_filters(entry, filters))
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        let scenario_order = left.scenario_id.cmp(&right.scenario_id);
        if scenario_order == Ordering::Equal {
            left.card_id.cmp(&right.card_id)
        } else {
            scenario_order
        }
    });

    Ok(entries)
}

fn decision_card_entry(record: &JsonlRecord) -> Option<DecisionCardEntry> {
    if record.value.get("record_type")?.as_str()? != "swarm_decision_card" {
        return None;
    }
    let card = record.value.get("card")?;
    let card_id = string_field(card, "card_id")?;
    let fallback = card.get("fallback").unwrap_or(&Value::Null);
    let counterfactual = card.get("counterfactual").unwrap_or(&Value::Null);
    let evidence_handles = card
        .get("evidence_pointers")
        .and_then(Value::as_array)
        .map(|pointers| {
            pointers
                .iter()
                .map(|pointer| {
                    json!({
                        "kind": pointer.get("kind").and_then(Value::as_str),
                        "handle": pointer.get("handle").and_then(Value::as_str),
                        "digest": pointer.get("digest").and_then(Value::as_str),
                        "redacted": pointer.get("redacted").and_then(Value::as_bool).unwrap_or(false),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let replayable_offline = card
        .get("replay_inputs")
        .and_then(Value::as_object)
        .is_some_and(|inputs| !inputs.is_empty())
        && !evidence_handles
            .iter()
            .any(|pointer| pointer.get("kind").and_then(Value::as_str) == Some("live_service"));

    Some(DecisionCardEntry {
        line: record.line,
        card_id,
        scenario_id: string_field(card, "scenario_id"),
        domain: string_field(card, "domain"),
        subject: string_field(card, "subject"),
        action: string_field(card, "action"),
        state: string_field(card, "state"),
        calibration: string_field(card, "calibration"),
        fallback_active: fallback
            .get("active")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        fallback_action: string_field(fallback, "action"),
        fallback_reason: string_field(fallback, "reason"),
        counterfactual_action: string_field(counterfactual, "action"),
        counterfactual_reason: string_field(counterfactual, "reason"),
        dominant_loss_term: dominant_loss_term(card),
        evidence_handles,
        replayable_offline,
        raw_record: record.value.clone(),
    })
}

fn matches_filters(entry: &DecisionCardEntry, filters: &SwarmEvidenceFilters) -> bool {
    string_filter_matches(filters.zone.as_deref(), &entry.raw_record)
        && string_filter_matches(filters.connector.as_deref(), &entry.raw_record)
        && string_filter_matches(filters.principal.as_deref(), &entry.raw_record)
        && string_filter_matches(filters.correlation_id.as_deref(), &entry.raw_record)
        && exact_or_deep_match(
            filters.scenario.as_deref(),
            entry.scenario_id.as_deref(),
            entry,
        )
        && exact_filter_matches(filters.action.as_deref(), entry.action.as_deref())
        && exact_filter_matches(
            filters.fallback_reason.as_deref(),
            entry.fallback_reason.as_deref(),
        )
        && exact_filter_matches(
            filters.dominant_loss_term.as_deref(),
            entry
                .dominant_loss_term
                .as_ref()
                .and_then(|term| term.get("name"))
                .and_then(Value::as_str),
        )
}

fn exact_or_deep_match(
    filter: Option<&str>,
    exact_value: Option<&str>,
    entry: &DecisionCardEntry,
) -> bool {
    match filter {
        None => true,
        Some(expected) => {
            exact_value.is_some_and(|actual| actual == expected)
                || value_contains_string(&entry.raw_record, expected)
        }
    }
}

fn string_filter_matches(filter: Option<&str>, record: &Value) -> bool {
    match filter {
        None => true,
        Some(needle) => value_contains_string(record, needle),
    }
}

fn exact_filter_matches(filter: Option<&str>, actual: Option<&str>) -> bool {
    match filter {
        None => true,
        Some(expected) => actual == Some(expected),
    }
}

fn value_contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.contains(needle),
        Value::Array(items) => items.iter().any(|item| value_contains_string(item, needle)),
        Value::Object(map) => map.values().any(|item| value_contains_string(item, needle)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn dominant_loss_term(card: &Value) -> Option<Value> {
    card.get("loss_terms")?
        .as_array()?
        .iter()
        .max_by_key(|term| {
            let value = term.get("value").and_then(Value::as_i64).unwrap_or(0);
            let weight = term
                .get("weight_microunits")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            i128::from(value).saturating_mul(i128::from(weight))
        })
        .map(|term| {
            let value = term.get("value").and_then(Value::as_i64).unwrap_or(0);
            let weight = term
                .get("weight_microunits")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            json!({
                "name": term.get("name").and_then(Value::as_str),
                "value": value,
                "weight_microunits": weight,
                "unit": term.get("unit").and_then(Value::as_str),
                "weighted_score": i128::from(value).saturating_mul(i128::from(weight)).to_string(),
            })
        })
}

fn entry_summary(entry: &DecisionCardEntry) -> Value {
    json!({
        "line": entry.line,
        "card_id": &entry.card_id,
        "scenario_id": &entry.scenario_id,
        "domain": &entry.domain,
        "subject": &entry.subject,
        "state": &entry.state,
        "action": &entry.action,
        "calibration": &entry.calibration,
        "fallback": {
            "active": entry.fallback_active,
            "action": &entry.fallback_action,
            "reason": &entry.fallback_reason,
        },
        "dominant_loss_term": &entry.dominant_loss_term,
        "counterfactual": {
            "action": &entry.counterfactual_action,
            "reason": &entry.counterfactual_reason,
        },
        "evidence_handles": &entry.evidence_handles,
        "replayable_offline": entry.replayable_offline,
    })
}

fn replay_summary(entry: &DecisionCardEntry) -> Value {
    let card = entry.raw_record.get("card").unwrap_or(&Value::Null);
    json!({
        "line": entry.line,
        "card_id": &entry.card_id,
        "answers": {
            "what_happened": {
                "scenario_id": &entry.scenario_id,
                "domain": &entry.domain,
                "subject": &entry.subject,
                "state": &entry.state,
                "selected_action": &entry.action,
            },
            "why_selected": {
                "selected_loss_score": card.get("selected_loss_score"),
                "dominant_loss_term": &entry.dominant_loss_term,
                "calibration": &entry.calibration,
            },
            "next_best_counterfactual": card
                .get("counterfactual")
                .map(redacted_value)
                .unwrap_or(Value::Null),
            "fallback": card.get("fallback").map(redacted_value).unwrap_or(Value::Null),
            "proof_locations": {
                "evidence_handles": &entry.evidence_handles,
                "replay_inputs": card
                    .get("replay_inputs")
                    .map(redacted_value)
                    .unwrap_or_else(|| json!({})),
            },
        },
        "replayable_offline": entry.replayable_offline,
        "redacted_record": redacted_value(&entry.raw_record),
    })
}

fn redacted_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(redacted_value).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| {
                    let value = if is_sensitive_key(key) {
                        json!("[redacted]")
                    } else {
                        redacted_value(item)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("authorization")
        || normalized.contains("credential")
        || normalized.contains("apikey")
        || normalized.contains("accesskey")
        || normalized.contains("privatekey")
        || normalized.contains("bearer")
}

fn bundle_summary(records: &[JsonlRecord], filtered_cards: usize) -> Value {
    let mut record_type_counts = serde_json::Map::new();
    for record in records {
        if let Some(record_type) = record.value.get("record_type").and_then(Value::as_str) {
            let count = record_type_counts
                .get(record_type)
                .and_then(Value::as_u64)
                .unwrap_or(0)
                + 1;
            record_type_counts.insert(record_type.to_owned(), json!(count));
        }
    }

    json!({
        "record_count": records.len(),
        "record_type_counts": Value::Object(record_type_counts),
        "decision_card_count": records.iter().filter_map(decision_card_entry).count(),
        "filtered_decision_card_count": filtered_cards,
    })
}

fn report_links(records: &[JsonlRecord]) -> Vec<Value> {
    records
        .iter()
        .filter_map(|record| {
            let record_type = record.value.get("record_type")?.as_str()?;
            if !matches!(
                record_type,
                "swarm_gauntlet_log"
                    | "swarm_gauntlet_summary"
                    | "swarm_controller_safety_report"
                    | "swarm_statistical_gate_report"
                    | "swarm_baseline_promotion_manifest"
                    | "swarm_promotion_skip"
            ) {
                return None;
            }
            Some(json!({
                "line": record.line,
                "record_type": record_type,
                "scenario": record
                    .value
                    .get("scenario")
                    .or_else(|| record.value.get("scenario_id"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "outcome": record.value.get("outcome").cloned().unwrap_or(Value::Null),
                "decision_card_ids": record
                    .value
                    .get("decision_card_ids")
                    .cloned()
                    .unwrap_or(Value::Null),
                "evidence_bundle_id": record
                    .value
                    .get("evidence_bundle_id")
                    .cloned()
                    .unwrap_or(Value::Null),
                "raw_samples_record_type": record
                    .value
                    .get("raw_samples_record_type")
                    .cloned()
                    .unwrap_or(Value::Null),
                "raw_sample_digest": record
                    .value
                    .get("raw_sample_digest")
                    .cloned()
                    .unwrap_or(Value::Null),
                "summary_digest": record.value.get("summary_digest").cloned().unwrap_or(Value::Null),
                "gate_report_digest": record
                    .value
                    .get("gate_report_digest")
                    .cloned()
                    .unwrap_or(Value::Null),
                "proof_notes_digest": record
                    .value
                    .get("proof_notes_digest")
                    .cloned()
                    .unwrap_or(Value::Null),
            }))
        })
        .collect()
}

fn format_explore_toon(payload: &Value) -> String {
    let returned = payload
        .get("pagination")
        .and_then(|value| value.get("returned"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total = payload
        .get("pagination")
        .and_then(|value| value.get("total_filtered"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut lines = vec![format!(
        "swarm-evidence cards returned={returned} filtered={total}"
    )];
    if let Some(entries) = payload.get("entries").and_then(Value::as_array) {
        for entry in entries.iter().take(10) {
            let card_id = entry
                .get("card_id")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let action = entry
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let domain = entry
                .get("domain")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            lines.push(format!("- {card_id} {domain} action={action}"));
        }
    }
    lines.join("\n")
}

fn format_replay_toon(payload: &Value) -> String {
    let mut lines = vec!["swarm-evidence replay".to_owned()];
    if let Some(entries) = payload.get("entries").and_then(Value::as_array) {
        for entry in entries.iter().take(10) {
            let card_id = entry
                .get("card_id")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let action = entry
                .pointer("/answers/what_happened/selected_action")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let fallback_active = entry
                .pointer("/answers/fallback/active")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            lines.push(format!(
                "- {card_id} selected={action} fallback_active={fallback_active}"
            ));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;

    use super::{
        SwarmEvidenceExploreArgs, SwarmEvidenceFilters, SwarmEvidenceReplayArgs, explore, replay,
    };

    fn write_fixture() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(
            file,
            "{}",
            json!({
                "record_type": "swarm_decision_card",
                "schema_version": "swarm-decision-card/v1",
                "card": {
                    "schema_version": "swarm-decision-card/v1",
                    "card_id": "card:1",
                    "scenario_id": "mixed_priority",
                    "domain": "scheduler",
                    "subject": "connector:fcp.github principal:user:1 zone:z:work correlation:corr-1",
                    "state": "queue_depth=12",
                    "action": "delay",
                    "selected_loss_score": 42,
                    "loss_terms": [
                        {"name": "p99_queueing", "value": 3, "weight_microunits": 1000, "unit": "ms"},
                        {"name": "zone_fairness", "value": 9, "weight_microunits": 2000, "unit": "skew"}
                    ],
                    "calibration": "valid",
                    "fallback": {"active": false, "action": "fallback", "reason": "calibration_valid"},
                    "counterfactual": {"action": "admit", "expected_loss_score": 80, "reason": "higher fairness loss"},
                    "evidence_pointers": [
                        {"kind": "bundle_artifact", "handle": "raw-samples.jsonl", "digest": "blake3:test", "redacted": true}
                    ],
                    "replay_inputs": {"queue_depth": 12, "auth_token": "must-not-leak"},
                    "created_at": "2026-05-05T00:00:00Z"
                }
            })
        )
        .expect("write fixture");
        writeln!(
            file,
            "{}",
            json!({
                "record_type": "swarm_decision_card",
                "schema_version": "swarm-decision-card/v1",
                "card": {
                    "schema_version": "swarm-decision-card/v1",
                    "card_id": "card:0",
                    "scenario_id": "capacity_baseline",
                    "domain": "scheduler",
                    "subject": "connector:fcp.slack principal:user:2 zone:z:project:alpha correlation:corr-2",
                    "state": "queue_depth=2",
                    "action": "admit",
                    "selected_loss_score": 7,
                    "loss_terms": [
                        {"name": "p99_queueing", "value": 7, "weight_microunits": 1000, "unit": "ms"}
                    ],
                    "calibration": "valid",
                    "fallback": {"active": false, "action": "delay", "reason": "healthy_capacity"},
                    "counterfactual": {"action": "delay", "expected_loss_score": 11, "reason": "unneeded queueing"},
                    "evidence_pointers": [
                        {"kind": "live_service", "handle": "runtime-host", "digest": "blake3:live", "redacted": false}
                    ],
                    "replay_inputs": {"queue_depth": 2},
                    "created_at": "2026-05-05T00:00:01Z"
                }
            })
        )
        .expect("write second fixture");
        writeln!(
            file,
            "{}",
            json!({
                "record_type": "swarm_controller_safety_report",
                "schema_version": "swarm-controller-safety/v1",
                "scenario": "mixed_priority",
                "outcome": "pass",
                "decision_card_ids": ["card:1", "card:0"]
            })
        )
        .expect("write report");
        file
    }

    #[test]
    fn explore_filters_cards_by_action_and_loss_term() {
        let file = write_fixture();
        let payload = explore(&SwarmEvidenceExploreArgs {
            file: file.path().to_path_buf(),
            filters: SwarmEvidenceFilters {
                action: Some("delay".to_owned()),
                dominant_loss_term: Some("zone_fairness".to_owned()),
                ..SwarmEvidenceFilters::default()
            },
            limit: 10,
            offset: 0,
        })
        .expect("explore");

        assert_eq!(payload["summary"]["filtered_decision_card_count"], 1);
        assert_eq!(payload["entries"][0]["card_id"], "card:1");
        assert_eq!(
            payload["entries"][0]["dominant_loss_term"]["name"],
            "zone_fairness"
        );
        assert_eq!(payload["reports"][0]["decision_card_ids"][0], "card:1");
    }

    #[test]
    fn replay_renders_operator_answers_without_live_services() {
        let file = write_fixture();
        let payload = replay(&SwarmEvidenceReplayArgs {
            file: file.path().to_path_buf(),
            card_ids: vec!["card:1".to_owned()],
            filters: SwarmEvidenceFilters::default(),
            limit: 10,
        })
        .expect("replay");

        assert_eq!(
            payload["entries"][0]["answers"]["what_happened"]["selected_action"],
            "delay"
        );
        assert_eq!(
            payload["entries"][0]["answers"]["next_best_counterfactual"]["action"],
            "admit"
        );
        assert_eq!(
            payload["entries"][0]["answers"]["proof_locations"]["evidence_handles"][0]["handle"],
            "raw-samples.jsonl"
        );
        assert_eq!(
            payload["entries"][0]["answers"]["proof_locations"]["replay_inputs"]["auth_token"],
            "[redacted]"
        );
        assert_eq!(
            payload["entries"][0]["redacted_record"]["card"]["replay_inputs"]["auth_token"],
            "[redacted]"
        );
        assert_eq!(payload["entries"][0]["replayable_offline"], true);
    }

    #[test]
    fn explore_sorts_paginates_and_preserves_redaction_metadata() {
        let file = write_fixture();
        let first_page = explore(&SwarmEvidenceExploreArgs {
            file: file.path().to_path_buf(),
            filters: SwarmEvidenceFilters::default(),
            limit: 1,
            offset: 0,
        })
        .expect("first page");

        assert_eq!(first_page["entries"][0]["card_id"], "card:0");
        assert_eq!(first_page["pagination"]["returned"], 1);
        assert_eq!(first_page["pagination"]["total_filtered"], 2);
        assert_eq!(first_page["pagination"]["has_more"], true);
        assert!(first_page.get("toon").is_some());

        let second_page = explore(&SwarmEvidenceExploreArgs {
            file: file.path().to_path_buf(),
            filters: SwarmEvidenceFilters::default(),
            limit: 1,
            offset: 1,
        })
        .expect("second page");

        assert_eq!(second_page["entries"][0]["card_id"], "card:1");
        assert_eq!(
            second_page["entries"][0]["evidence_handles"][0]["redacted"],
            true
        );
        assert_eq!(second_page["pagination"]["has_more"], false);
        assert_eq!(
            second_page["reports"][0]["record_type"],
            "swarm_controller_safety_report"
        );
    }
}
