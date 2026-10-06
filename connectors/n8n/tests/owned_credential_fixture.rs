//! Dedicated test executable: reuse the original connector child wire loop.
//! No command-line, environment, endpoint or key trust override is exposed.

#[path = "../src/main.rs"]
mod original_connector;

fn main() -> anyhow::Result<()> {
    original_connector::owned_credential_fixture_entrypoint()
}
