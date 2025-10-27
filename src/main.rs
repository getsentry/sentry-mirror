use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use log::info;
use tokio::net::TcpListener;

mod config;
mod dsn;
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

    // Config logging
    if args.verbose {
        simple_logger::init_with_level(log::Level::Debug).unwrap();
    } else {
        simple_logger::init_with_level(log::Level::Info).unwrap();
    }

    let config_path = Path::new(&args.config);
    info!("Using configuration file {0}", args.config);

    // Parse the configuration file
    let configdata = match config::load_config(config_path) {
        Ok(keys) => keys,
        Err(_) => {
            println!("Invalid configuration file");
            panic!("Could not parse configuration file");
        }
    };

    let port = configdata
        .port
        .expect("Missing required configuration `port`");
    let ip = configdata
        .ip
        .or_else(|| Some("127.0.0.1".to_string()))
        .unwrap();

    let addr = format!("{ip}:{port}");
    info!("Listening on {0}", addr);
    let listener = TcpListener::bind(addr).await?;

    // Create keymap that we need to match incoming requests
    let keymap = dsn::make_key_map(configdata.keys);
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
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
