use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::pin;
use std::time::Duration;

use axum::{Router, body::Body};
use clap::Parser;
use fcp_async_core::{
    hyper_bridge::{HyperExecutor, HyperIo},
    net::TcpListener,
    task,
};
use fcp_registry::LocalRegistryCatalog;
use hyper::body::Incoming;
use hyper_util::{
    server::conn::auto::Builder as HyperConnectionBuilder, service::TowerToHyperService,
};
use tower::ServiceExt;

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

fn hyper_executor() -> HyperExecutor {
    HyperExecutor::with_spawn_fn(|future| {
        task::spawn_detached(future);
    })
}

fn spawn_http_connection<IO>(io: IO, app: Router)
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let tower_service = app.map_request(|request: hyper::Request<Incoming>| request.map(Body::new));
    let hyper_service = TowerToHyperService::new(tower_service);

    task::spawn_detached(async move {
        let mut builder = HyperConnectionBuilder::new(hyper_executor());
        builder.http2().enable_connect_protocol();

        let mut connection = pin!(builder.serve_connection_with_upgrades(io, hyper_service));
        if let Err(err) = connection.as_mut().await {
            eprintln!("fcp-registry-server connection error: {err}");
        }
    });
}

async fn handle_accept_error(err: std::io::Error) {
    if matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    ) {
        return;
    }

    eprintln!("fcp-registry-server accept error: {err}");
    fcp_async_core::time::sleep(Duration::from_secs(1)).await;
}

async fn serve_tcp(listener: TcpListener, app: Router) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => spawn_http_connection(HyperIo::new(stream), app.clone()),
            Err(err) => handle_accept_error(err).await,
        }
    }
}

#[fcp_async_core::runtime::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let catalog = LocalRegistryCatalog::from_signed_package_dirs(&args.package_dirs)?;
    let connector_count = catalog.connectors_response().connectors.len();
    let app = catalog.router();

    let listener = TcpListener::bind(args.listen).await?;
    let local_addr = listener.local_addr()?;
    eprintln!("fcp-registry-server serving {connector_count} connector(s) at http://{local_addr}");
    serve_tcp(listener, app).await?;
    Ok(())
}
