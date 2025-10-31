use crate::Args;
use figment::{
    providers::{Env, Format, Yaml}, Figment, Metadata, Profile, Provider
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;

use crate::logging::LogFormat;

/// A set of inbound and outbound keys.
/// Requests sent to an inbound DSN are mirrored to all outbound DSNs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub default_metrics_tags: Option<BTreeMap<String, String>>,

    /// The inbound IP to use. Defaults to 127.0.0.1
    pub ip: String,

    /// The port the http server will listen on
    pub port: u16,

    /// Whether or not verbose mode was enabled.
    /// When enabled, debug logging will be output.
    pub verbose: bool,

    /// A list of keypairs that the server will handle.
    pub keys: Vec<KeyRing>,
}

impl ConfigData {
    /// Get the tcp address to bind an http server to
    pub fn bind_addr(&self) -> String {
        let port = self.port;
        let ip = self.ip.clone();

        format!("{ip}:{port}")
    }
}

impl Default for ConfigData {
    fn default() -> Self {
        Self {
            sentry_dsn: None,
            sentry_env: None,
            traces_sample_rate: None,
            log_filter: None,
            log_format: None,
            statsd_addr: None,
            default_metrics_tags: None,
            ip: "127.0.0.1".into(),
            port: 3000,
            verbose: false,
            keys: vec![],
        }
    }
}

impl Provider for ConfigData {
    fn metadata(&self) -> Metadata {
        Metadata::named("sentry-mirror defaults")
    }

    fn data(&self) -> Result<figment::value::Map<Profile, figment::value::Dict>, figment::Error> {
        figment::providers::Serialized::defaults(ConfigData::default()).data()
    }
}

pub fn from_args(args: &Args) -> Result<ConfigData, Box<figment::Error>> {
    let config_path = &args.config;
    let config: ConfigData = Figment::from(ConfigData::default())
        .merge(Env::prefixed("SENTRY_MIRROR_"))
        .merge(Yaml::file(config_path))
        .extract()?;

    Ok(config)
}

pub fn get_version() -> &'static str {
    let release_name = fs::read_to_string("./VERSION").expect("Unable to read version");
    Box::leak(release_name.into_boxed_str())
}
