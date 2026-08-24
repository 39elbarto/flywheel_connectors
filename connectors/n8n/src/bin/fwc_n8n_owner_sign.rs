//! Offline owner-side signer for an already materialized n8n release.
//!
//! The target is feature-gated and is never linked into the normal runtime
//! binary. It accepts only a release identifier, a bounded non-secret request
//! file, and the KeePass-provided Base64 seed on stdin.

use std::{fs, io, io::Read, io::Write, path::Path, process::ExitCode};

use clap::Parser;
use serde::Deserialize;

#[path = "fwc_n8n_bundle.rs"]
#[allow(dead_code)]
mod fwc_n8n_bundle;
#[path = "fwc_n8n_owner_signing.rs"]
mod fwc_n8n_owner_signing;
#[path = "fwc_n8n_provision.rs"]
#[allow(dead_code)]
mod fwc_n8n_provision;

const PROVISION_INPUT_SCHEMA: &str = "fwc.n8n.provision-request.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "fwc-n8n-owner-sign",
    version,
    about = "Offline owner signer for a staged fwc-n8n release"
)]
struct Cli {
    /// Exact release identifier. The signer derives the fixed staging path.
    #[arg(long)]
    release_id: String,
    /// Bounded, non-secret fwc.n8n.provision-request.v1 JSON file.
    #[arg(long)]
    request_file: std::path::PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequest {
    schema: String,
    release_id: String,
    git_revision: String,
    bindings: Vec<fwc_n8n_provision::OfficialMcpBinding>,
}

fn main() -> ExitCode {
    match run() {
        Ok(receipt) => {
            let mut stdout = io::stdout().lock();
            if stdout.write_all(&receipt).is_err() || stdout.write_all(b"\n").is_err() {
                eprintln!("fwc-n8n-owner-sign: output_failed");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Err(()) => {
            eprintln!("fwc-n8n-owner-sign: owner_sign_failed");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<Vec<u8>, ()> {
    let cli = Cli::parse();
    let request_bytes = read_bounded_regular_file(&cli.request_file, MAX_REQUEST_BYTES)?;
    let request: SigningRequest = serde_json::from_slice(&request_bytes).map_err(|_| ())?;
    if request.schema != PROVISION_INPUT_SCHEMA || request.release_id != cli.release_id {
        return Err(());
    }
    let seed = fwc_n8n_owner_signing::read_seed_from_stdin()?;
    fwc_n8n_owner_signing::sign_staged_provision_receipt(
        &cli.release_id,
        &request.git_revision,
        request.bindings,
        &seed,
    )
    .map_err(|_| ())
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ()> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(());
    }
    if fs::canonicalize(path).map_err(|_| ())? != path {
        return Err(());
    }
    let mut file = fs::File::open(path).map_err(|_| ())?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| ())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes).map_err(|_| ())?;
    if u64::try_from(bytes.len()).map_err(|_| ())? > max_bytes {
        return Err(());
    }
    Ok(bytes)
}
