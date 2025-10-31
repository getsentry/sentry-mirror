use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
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
    let config_path = Path::new(&args.config);
    println!("sentry-mirror starting");
    println!("version: {0}", config::get_version());
    println!("configuration file: {0}", args.config);

    // Parse the configuration file
    let configdata = match config::load_config(config_path) {
        Ok(keys) => keys,
        Err(err) => {
            panic!("Could not parse configuration file: {err:?}");
        }
    };

    // Initialize metrics and logging
    metrics::init(metrics::MetricsConfig::from_config(&configdata));
    logging::init(logging::LoggingConfig::from_config(
        &configdata,
        args.verbose,
    ));

    let addr = configdata.bind_addr();
    info!("Listening on {addr}");
    let listener = TcpListener::bind(addr).await?;

    // Create keymap that we need to match incoming requests
    let keymap = dsn::make_key_map(configdata.keys);
    debug!("DSN configuration");
    debug!("{}", dsn::format_key_map(&keymap));
    let arcmap = Arc::new(keymap);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let arcmap_loop = arcmap.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req: Request<Incoming>| {
                        service::handle_request(req, arcmap_loop.clone())
                    }),
                )
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}
