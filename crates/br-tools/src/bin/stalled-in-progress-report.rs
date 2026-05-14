use std::{collections::BTreeSet, env, error::Error, path::PathBuf, process::Command};

use br_tools::stalled_in_progress::{
    DEFAULT_RECENT_COMMENT_HOURS, DEFAULT_STALE_AFTER_HOURS, ProcessSnapshot, ReportConfig,
    build_report, default_write_lock_path, load_issue_records, render_table,
};
use chrono::{DateTime, Duration, Utc};

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env(env::args().skip(1))?;
    let mut report_config = ReportConfig {
        now: config.now,
        stale_after: Duration::hours(config.stale_after_hours),
        recent_comment_after: Duration::hours(config.recent_comment_hours),
        lock_present: config.lock_path.exists(),
        lock_path: Some(config.lock_path),
        active_processes: config.processes,
        known_agents: config.known_agents,
    };
    if !config.skip_ps {
        report_config
            .active_processes
            .extend(collect_ps_processes());
    }

    let issues = load_issue_records(&config.issues_jsonl)?;
    let report = build_report(&issues, &report_config);

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
    lock_path: PathBuf,
    now: DateTime<Utc>,
    stale_after_hours: i64,
    recent_comment_hours: i64,
    known_agents: BTreeSet<String>,
    processes: Vec<ProcessSnapshot>,
    skip_ps: bool,
    format: Format,
}

impl Config {
    fn from_env(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut issues_jsonl = PathBuf::from(".beads/issues.jsonl");
        let mut lock_path = default_write_lock_path();
        let mut now = Utc::now();
        let mut stale_after_hours = DEFAULT_STALE_AFTER_HOURS;
        let mut recent_comment_hours = DEFAULT_RECENT_COMMENT_HOURS;
        let mut known_agents = BTreeSet::new();
        let mut processes = Vec::new();
        let mut skip_ps = false;
        let mut format = Format::Table;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--issues" => issues_jsonl = PathBuf::from(next_value(&mut iter, "--issues")?),
                "--lock-path" => lock_path = PathBuf::from(next_value(&mut iter, "--lock-path")?),
                "--now" => now = parse_now(&next_value(&mut iter, "--now")?)?,
                "--stale-after-hours" => {
                    stale_after_hours =
                        parse_positive_hours(&next_value(&mut iter, "--stale-after-hours")?)?;
                }
                "--recent-comment-hours" => {
                    recent_comment_hours =
                        parse_positive_hours(&next_value(&mut iter, "--recent-comment-hours")?)?;
                }
                "--active-agent" => {
                    known_agents.insert(next_value(&mut iter, "--active-agent")?);
                }
                "--process" => processes.push(ProcessSnapshot::new(
                    None,
                    next_value(&mut iter, "--process")?,
                )),
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
            lock_path,
            now,
            stale_after_hours,
            recent_comment_hours,
            known_agents,
            processes,
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

fn parse_positive_hours(raw: &str) -> Result<i64, String> {
    let value = raw
        .parse::<i64>()
        .map_err(|err| format!("invalid hour value {raw:?}: {err}"))?;
    if value <= 0 {
        return Err(format!("hour value must be positive, got {value}"));
    }
    Ok(value)
}

fn next_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}\n{}", usage()))
}

const fn usage() -> &'static str {
    "usage: stalled-in-progress-report [--issues PATH] [--lock-path PATH] [--now RFC3339] [--stale-after-hours N] [--recent-comment-hours N] [--active-agent NAME] [--process COMMAND] [--no-ps] [--table|--json|--both]"
}
