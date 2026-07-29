use std::{env, error::Error, path::PathBuf};

use br_tools::incident_fixture_corpus::{
    IncidentReplayConfig, build_replay_report, default_fixture_dir, load_fixture_dir, render_table,
    write_report_outputs,
};
use chrono::{DateTime, Utc};

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env(env::args().skip(1))?;
    let fixtures = load_fixture_dir(&config.fixture_dir)?;
    let report = build_replay_report(
        &fixtures,
        &IncidentReplayConfig {
            now: config.now,
            corpus_dir: Some(config.fixture_dir.clone()),
        },
    );
    write_report_outputs(
        &report,
        config.summary_json.as_deref(),
        config.events_jsonl.as_deref(),
    )?;

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
    fixture_dir: PathBuf,
    summary_json: Option<PathBuf>,
    events_jsonl: Option<PathBuf>,
    now: DateTime<Utc>,
    format: Format,
}

impl Config {
    fn from_env(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut fixture_dir = default_fixture_dir();
        let mut summary_json = None;
        let mut events_jsonl = None;
        let mut now = Utc::now();
        let mut format = Format::Table;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--fixtures" => fixture_dir = PathBuf::from(next_value(&mut iter, "--fixtures")?),
                "--summary-json" => {
                    summary_json = Some(PathBuf::from(next_value(&mut iter, "--summary-json")?));
                }
                "--events-jsonl" => {
                    events_jsonl = Some(PathBuf::from(next_value(&mut iter, "--events-jsonl")?));
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

        Ok(Self {
            fixture_dir,
            summary_json,
            events_jsonl,
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
    "usage: incident-fixture-replay [--fixtures PATH] [--summary-json PATH] [--events-jsonl PATH] [--now RFC3339] [--table|--json|--both]"
}
