use std::{env, error::Error, path::PathBuf, process::Command};

use br_tools::state_integrity::{
    DEFAULT_LOCK_STALE_AFTER_SECONDS, ProcessSnapshot, StateIntegrityConfig,
    build_state_integrity_report, default_beads_db_path, default_issues_jsonl_path,
    default_write_lock_path, load_bv_graph_source, load_db_snapshot_source, load_jsonl_source,
    load_live_db_source, render_table,
};
use chrono::{DateTime, Duration, Utc};

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env(env::args().skip(1))?;
    let mut report_config = StateIntegrityConfig {
        now: config.now,
        lock_path: Some(config.lock_path.clone()),
        lock_stale_after: Duration::seconds(config.lock_stale_after_seconds),
        active_processes: config.processes,
        query_issue_id: config.query_issue_id.clone(),
    };
    if !config.skip_ps {
        report_config
            .active_processes
            .extend(collect_ps_processes());
    }

    let jsonl = load_jsonl_source(&config.issues_jsonl);
    let db = match config.db_source.as_ref() {
        Some(DbSourceConfig::Live(path)) => Some(load_live_db_source(path)),
        Some(DbSourceConfig::Snapshot(path)) => Some(load_db_snapshot_source(path)),
        None => None,
    };
    let bv = config
        .bv_graph
        .as_ref()
        .map(|path| load_bv_graph_source(path));
    let report = build_state_integrity_report(jsonl, db, bv, &report_config);

    match config.format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        Format::Table => print!("{}", render_table(&report)),
        Format::Both => {
            print!("{}", render_table(&report));
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    Ok(())
}

#[derive(Debug)]
struct Config {
    issues_jsonl: PathBuf,
    db_source: Option<DbSourceConfig>,
    bv_graph: Option<PathBuf>,
    lock_path: PathBuf,
    now: DateTime<Utc>,
    lock_stale_after_seconds: i64,
    processes: Vec<ProcessSnapshot>,
    query_issue_id: Option<String>,
    skip_ps: bool,
    format: Format,
}

#[derive(Debug)]
enum DbSourceConfig {
    Live(PathBuf),
    Snapshot(PathBuf),
}

impl Config {
    fn from_env(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut issues_jsonl = default_issues_jsonl_path();
        let mut db_source = Some(DbSourceConfig::Live(default_beads_db_path()));
        let mut bv_graph = None;
        let mut lock_path = default_write_lock_path();
        let mut now = Utc::now();
        let mut lock_stale_after_seconds = DEFAULT_LOCK_STALE_AFTER_SECONDS;
        let mut processes = Vec::new();
        let mut query_issue_id = None;
        let mut skip_ps = false;
        let mut format = Format::Table;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--issues" => issues_jsonl = PathBuf::from(next_value(&mut iter, "--issues")?),
                "--db" => {
                    db_source = Some(DbSourceConfig::Live(PathBuf::from(next_value(
                        &mut iter, "--db",
                    )?)));
                }
                "--db-snapshot" => {
                    db_source = Some(DbSourceConfig::Snapshot(PathBuf::from(next_value(
                        &mut iter,
                        "--db-snapshot",
                    )?)));
                }
                "--no-db" => db_source = None,
                "--bv-graph" => {
                    bv_graph = Some(PathBuf::from(next_value(&mut iter, "--bv-graph")?));
                }
                "--lock-path" => lock_path = PathBuf::from(next_value(&mut iter, "--lock-path")?),
                "--now" => now = parse_now(&next_value(&mut iter, "--now")?)?,
                "--lock-stale-after-seconds" => {
                    lock_stale_after_seconds = parse_positive_seconds(&next_value(
                        &mut iter,
                        "--lock-stale-after-seconds",
                    )?)?;
                }
                "--process" => processes.push(ProcessSnapshot::new(
                    None,
                    next_value(&mut iter, "--process")?,
                )),
                "--issue" => query_issue_id = Some(next_value(&mut iter, "--issue")?),
                "--no-ps" => skip_ps = true,
                "--json" => format = Format::Json,
                "--both" => format = Format::Both,
                "--table" => format = Format::Table,
                "--help" | "-h" => {
                    println!("{}", usage());
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument {unknown:?}\n{}", usage())),
            }
        }

        Ok(Self {
            issues_jsonl,
            db_source,
            bv_graph,
            lock_path,
            now,
            lock_stale_after_seconds,
            processes,
            query_issue_id,
            skip_ps,
            format,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Table,
    Both,
}

fn collect_ps_processes() -> Vec<ProcessSnapshot> {
    let Ok(output) = Command::new("ps").args(["-axo", "pid=,command="]).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_process_line)
        .collect()
}

fn parse_process_line(line: &str) -> Option<ProcessSnapshot> {
    let trimmed = line.trim_start();
    let split_at = trimmed.find(char::is_whitespace)?;
    let (pid, command) = trimmed.split_at(split_at);
    Some(ProcessSnapshot::new(pid.parse().ok(), command.trim_start()))
}

fn parse_now(raw: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(DateTime::from)
        .map_err(|err| format!("invalid --now value {raw:?}: {err}"))
}

fn parse_positive_seconds(raw: &str) -> Result<i64, String> {
    let value = raw
        .parse::<i64>()
        .map_err(|err| format!("invalid second value {raw:?}: {err}"))?;
    if value <= 0 {
        return Err(format!("second value must be positive, got {value}"));
    }
    Ok(value)
}

fn next_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}\n{}", usage()))
}

const fn usage() -> &'static str {
    "usage: beads-state-integrity [--issues PATH] [--db PATH|--db-snapshot PATH|--no-db] [--bv-graph PATH] [--issue ID] [--lock-path PATH] [--now RFC3339] [--lock-stale-after-seconds N] [--process COMMAND] [--no-ps] [--table|--json|--both]"
}
