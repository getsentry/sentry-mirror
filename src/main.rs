use std::sync::Arc;

use clap::Parser;
use http_body_util::Full;
use hyper::{body::Bytes, Request};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::{TokioExecutor, TokioIo}};
use tokio::net::TcpListener;
use tracing::{debug, error, info};

mod config;
mod dsn;
mod logging;
mod metrics;
mod request;
mod service;

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
    let configdata = Arc::new(config::from_args(&args)?);

    // Initialize metrics and logging
    metrics::init(metrics::MetricsConfig::from_config(&configdata));
    logging::init(logging::LoggingConfig::from_config(&configdata));

    let addr = configdata.bind_addr();
    info!("Listening on {addr}");
    let listener = TcpListener::bind(addr).await?;

    // Create a map of inbound -> outbound keys for simpler lookups.
    let keymap = Arc::new(dsn::make_key_map(configdata.keys.clone()));

    if configdata.verbose {
        debug!("DSN configuration");
        debug!("{}", dsn::format_key_map(&keymap));
    }

    let https = HttpsConnector::new();
    let arc_client = Arc::new(Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https));

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let keymap_loop = keymap.clone();
        let configdata_loop = configdata.clone();
        let client_loop = arc_client.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req: Request<Incoming>| {
                        let config_loop = configdata_loop.clone();
                        service::handle_request(req, config_loop.clone(), keymap_loop.clone(), client_loop.clone())
                    }),
                )
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}
