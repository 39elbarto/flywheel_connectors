use std::{env, error::Error, path::PathBuf};

use br_tools::scheduled_reality_check::{
    check_reality_cadence_with_existing, default_issues_jsonl, default_quarterly_dir,
    default_reality_dir, load_existing_beads,
};
use chrono::{NaiveDate, Utc};

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env(env::args().skip(1))?;
    let existing = if config.issues_jsonl.exists() {
        load_existing_beads(&config.issues_jsonl)?
    } else {
        Vec::new()
    };
    let proposed = check_reality_cadence_with_existing(
        config.today,
        &config.reality_dir,
        &config.quarterly_dir,
        &existing,
    );

    if config.json {
        println!("{}", serde_json::to_string_pretty(&proposed)?);
    } else if proposed.is_empty() {
        println!("reality-check cadence is current");
    } else {
        for bead in proposed {
            println!("{} [P{}]", bead.title, bead.priority);
        }
    }

    Ok(())
}

#[derive(Debug)]
struct Config {
    today: NaiveDate,
    reality_dir: PathBuf,
    quarterly_dir: PathBuf,
    issues_jsonl: PathBuf,
    json: bool,
}

impl Config {
    fn from_env(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut today = Utc::now().date_naive();
        let mut reality_dir = default_reality_dir();
        let mut quarterly_dir = default_quarterly_dir();
        let mut issues_jsonl = default_issues_jsonl();
        let mut json = false;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--today" => {
                    let raw = next_value(&mut iter, "--today")?;
                    today = NaiveDate::parse_from_str(&raw, "%Y-%m-%d")
                        .map_err(|err| format!("invalid --today value {raw:?}: {err}"))?;
                }
                "--reality-dir" => {
                    reality_dir = PathBuf::from(next_value(&mut iter, "--reality-dir")?);
                }
                "--quarterly-dir" => {
                    quarterly_dir = PathBuf::from(next_value(&mut iter, "--quarterly-dir")?);
                }
                "--issues" => {
                    issues_jsonl = PathBuf::from(next_value(&mut iter, "--issues")?);
                }
                "--json" => json = true,
                "--help" | "-h" => {
                    println!("{}", usage());
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument {unknown:?}\n{}", usage())),
            }
        }

        Ok(Self {
            today,
            reality_dir,
            quarterly_dir,
            issues_jsonl,
            json,
        })
    }
}

fn next_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}\n{}", usage()))
}

const fn usage() -> &'static str {
    "usage: scheduled-reality-check [--today YYYY-MM-DD] [--reality-dir PATH] [--quarterly-dir PATH] [--issues PATH] [--json]"
}
