use std::sync::Arc;

use clap::Parser;
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::state::AppState;

mod config;
mod dsn;
mod envelope;
mod logging;
mod metrics;
mod request;
mod sampling;
mod service;
mod state;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser, Debug)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: String,

    /// Whether or not to enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read command line options
    let args = Args::parse();
    println!("sentry-mirror starting");
    println!("version: {0}", config::get_version());
    println!("configuration file: {0}", args.config);

    // Parse the configuration file
    let configdata = config::from_args(&args)?;

    // Initialize metrics and logging
    metrics::init(metrics::MetricsConfig::from_config(&configdata));
    logging::init(logging::LoggingConfig::from_config(&configdata));

    let addr = configdata.bind_addr();
    info!("Listening on {addr}");
    let listener = TcpListener::bind(addr).await?;

    let state = Arc::new(AppState::from_config(configdata));

    if state.config.verbose {
        debug!("DSN configuration");
        debug!("{}", dsn::format_key_map(&state.keymap));
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state_loop = state.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req: Request<Incoming>| {
                        service::handle_request(req, state_loop.clone())
                    }),
                )
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}
