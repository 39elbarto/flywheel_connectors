use std::{env, error::Error, path::PathBuf};

use br_tools::ready_queue_reconciler::{
    ReadyQueueConfig, build_ready_queue_report, load_br_snapshot_source, load_bv_triage_source,
    load_jsonl_source, render_table,
};
use chrono::{DateTime, Utc};

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env(env::args().skip(1))?;
    let jsonl = load_jsonl_source(&config.issues_jsonl);
    let bv = load_bv_triage_source(&config.bv_triage);
    let br_snapshot = config.br_snapshot.as_deref().map(load_br_snapshot_source);
    let report = build_ready_queue_report(
        jsonl,
        bv,
        br_snapshot,
        &ReadyQueueConfig::default_with_now(config.now),
    );

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
    bv_triage: PathBuf,
    br_snapshot: Option<PathBuf>,
    now: DateTime<Utc>,
    format: Format,
}

impl Config {
    fn from_env(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut issues_jsonl = PathBuf::from(".beads/issues.jsonl");
        let mut bv_triage = None;
        let mut br_snapshot = None;
        let mut now = Utc::now();
        let mut format = Format::Table;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--issues" => issues_jsonl = PathBuf::from(next_value(&mut iter, "--issues")?),
                "--bv-triage" => {
                    bv_triage = Some(PathBuf::from(next_value(&mut iter, "--bv-triage")?));
                }
                "--br-snapshot" => {
                    br_snapshot = Some(PathBuf::from(next_value(&mut iter, "--br-snapshot")?));
                }
                "--now" => now = parse_now(&next_value(&mut iter, "--now")?)?,
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

        let Some(bv_triage) = bv_triage else {
            return Err(format!("missing required --bv-triage PATH\n{}", usage()));
        };

        Ok(Self {
            issues_jsonl,
            bv_triage,
            br_snapshot,
            now,
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

fn parse_now(raw: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(DateTime::from)
        .map_err(|err| format!("invalid --now value {raw:?}: {err}"))
}

fn next_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}\n{}", usage()))
}

const fn usage() -> &'static str {
    "usage: ready-queue-reconciler --bv-triage PATH [--issues PATH] [--br-snapshot PATH] [--now RFC3339] [--table|--json|--both]"
}
