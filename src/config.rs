use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::Path;
use std::{fs, io};

use crate::logging::LogFormat;

/// A set of inbound and outbound keys.
/// Requests sent to an inbound DSN are mirrored to all outbound DSNs
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyRing {
    /// Inbound keys are virtual DSNs that the mirror will accept traffic on
    pub inbound: Option<String>,
    /// One or more upstream DSN keys that the mirror will forward traffic to.
    pub outbound: Vec<Option<String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigData {
    /// The sentry DSN to use for error reporting, and tracing.
    pub sentry_dsn: Option<String>,

    /// The environment to report to sentry errors to.
    pub sentry_env: Option<Cow<'static, str>>,

    /// The sampling rate for tracing data.
    pub traces_sample_rate: Option<f32>,

    /// The log filter to apply application logging to.
    /// See https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives
    pub log_filter: Option<String>,

    /// The log format to use
    pub log_format: Option<LogFormat>,

    /// The statsd address to report metrics to.
    pub statsd_addr: Option<String>,

    /// Default tags to add to all metrics.
    pub default_metrics_tags: BTreeMap<String, String>,

    /// The inbound IP to use. Defaults to 127.0.0.1
    pub ip: Option<String>,

    /// The port the http server will listen on
    pub port: Option<u16>,

    /// A list of keypairs that the server will handle.
    pub keys: Vec<KeyRing>,
}

impl ConfigData {
    /// Get the tcp address to bind an http server to
    pub fn bind_addr(&self) -> String {
        let port = self
            .port
            .expect("Missing required configuration `port`");
        let ip = self
            .ip
            .clone()
            .or(Some("127.0.0.1".to_string()))
            .unwrap();

        format!("{ip}:{port}")
    }
}

/// Load configuration data from a path and parse it into `ConfigData`
pub fn load_config(path: &Path) -> Result<ConfigData, String> {
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Err(format!("{}", path.display())),
    };
    let configdata = match serde_yaml::from_reader(io::BufReader::new(f)) {
        Ok(data) => data,
        Err(err) => return Err(format!("{}", err)),
    };
    Ok(configdata)
}

pub fn get_version() -> &'static str {
    let release_name = fs::read_to_string("./VERSION").expect("Unable to read version");
    Box::leak(release_name.into_boxed_str())
}
