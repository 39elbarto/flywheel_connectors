use std::{env, error::Error, path::PathBuf, process::Command};

use br_tools::rch_toolchain_doctor::{
    RchToolchainDoctorConfig, WorkerObservationSource, build_rch_toolchain_doctor_report,
    load_diagnose_evidence, load_toolchain_requirement, load_worker_observation, render_table,
};
use chrono::{DateTime, Utc};

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env(env::args().skip(1))?;
    let report_config = RchToolchainDoctorConfig {
        now: config.now,
        git_revision: config.git_revision.or_else(current_git_revision),
        required_toolchain_override: config.required_toolchain,
    };
    let repo_toolchain = load_toolchain_requirement(&config.toolchain_toml);
    let diagnose = load_diagnose_evidence(config.diagnose_json.as_deref(), &config.diagnose_lines);
    let workers = config
        .worker_observations
        .iter()
        .map(|path| load_worker_observation(path))
        .collect::<Vec<WorkerObservationSource>>();
    let report =
        build_rch_toolchain_doctor_report(repo_toolchain, diagnose, &workers, &report_config);

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
    toolchain_toml: PathBuf,
    diagnose_json: Option<PathBuf>,
    diagnose_lines: Vec<String>,
    worker_observations: Vec<PathBuf>,
    required_toolchain: Option<String>,
    git_revision: Option<String>,
    now: DateTime<Utc>,
    format: Format,
}

impl Config {
    fn from_env(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut toolchain_toml = PathBuf::from("rust-toolchain.toml");
        let mut diagnose_json = None;
        let mut diagnose_lines = Vec::new();
        let mut worker_observations = Vec::new();
        let mut required_toolchain = None;
        let mut git_revision = None;
        let mut now = Utc::now();
        let mut format = Format::Table;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--toolchain-toml" => {
                    toolchain_toml = PathBuf::from(next_value(&mut iter, "--toolchain-toml")?);
                }
                "--diagnose-json" => {
                    diagnose_json = Some(PathBuf::from(next_value(&mut iter, "--diagnose-json")?));
                }
                "--diagnose-line" => {
                    diagnose_lines.push(next_value(&mut iter, "--diagnose-line")?);
                }
                "--worker-observation" => {
                    worker_observations.push(PathBuf::from(next_value(
                        &mut iter,
                        "--worker-observation",
                    )?));
                }
                "--required-toolchain" => {
                    required_toolchain = Some(next_value(&mut iter, "--required-toolchain")?);
                }
                "--git-revision" => git_revision = Some(next_value(&mut iter, "--git-revision")?),
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
            toolchain_toml,
            diagnose_json,
            diagnose_lines,
            worker_observations,
            required_toolchain,
            git_revision,
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

fn current_git_revision() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

const fn usage() -> &'static str {
    "usage: rch-toolchain-doctor [--toolchain-toml PATH] [--diagnose-json PATH] [--diagnose-line LINE] [--worker-observation PATH]... [--required-toolchain TOOLCHAIN] [--git-revision REV] [--now RFC3339] [--table|--json|--both]"
}
