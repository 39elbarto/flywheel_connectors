use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use fcp_registry::LocalRegistryCatalog;

#[derive(Debug, Parser)]
#[command(
    name = "fcp-registry-server",
    about = "Serve signed connector packages over a minimal local HTTP registry"
)]
struct Args {
    /// Listen address for the local registry server.
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,

    /// Signed package directories to expose through the registry.
    #[arg(long = "package-dir", required = true)]
    package_dirs: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let catalog = LocalRegistryCatalog::from_signed_package_dirs(&args.package_dirs)?;
    let connector_count = catalog.connectors_response().connectors.len();
    let app = catalog.router();

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    let local_addr = listener.local_addr()?;
    eprintln!("fcp-registry-server serving {connector_count} connector(s) at http://{local_addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
