use crate::Args;
use figment::{
    Figment, Metadata, Profile, Provider,
    providers::{Env, Format, Yaml},
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;

use crate::logging::LogFormat;

/// Configuration data for Outbound destination DSNs.
/// Each outbound DSN can optionally include a list of
/// `categories` that the DSN is interested in.Envelope
/// items that do not match an outbound key's `categories`
/// will be removed from requests sent to that DSN.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OutboundConfig {
    /// Shorthand: just a DSN string
    Dsn(Option<String>),
    // DSNs can also have additional settings defined for them using a dictionary
    Detailed {
        dsn: String,
        categories: Option<Vec<String>>,
        #[serde(default = "default_multiplier")]
        multiplier: usize,
    },
}

fn default_multiplier() -> usize {
    1
}

/// A set of inbound and outbound keys.
/// Requests sent to an inbound DSN are mirrored to all outbound DSNs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigKeyPair {
    /// Inbound keys are virtual DSNs that the mirror will accept traffic on
    pub inbound: String,

    /// One or more upstream DSN keys that the mirror will forward traffic to.
    pub outbound: Vec<OutboundConfig>,
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
    pub log_filter: String,

    /// The log format to use
    pub log_format: LogFormat,

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
    pub keys: Vec<ConfigKeyPair>,

    /// Set to false to skip rewriting envelope headers.
    /// Disaling envelope header modification makes mirroring more efficient,
    /// but requires the downstream relay to not be validating projectids/dsns in the envelope
    /// headers.
    pub modify_envelope: bool,
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
            log_filter: "info".into(),
            log_format: LogFormat::Text,
            statsd_addr: None,
            default_metrics_tags: None,
            ip: "127.0.0.1".into(),
            port: 3000,
            verbose: false,
            keys: vec![],
            modify_envelope: true,
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
    let mut config: ConfigData = Figment::from(ConfigData::default())
        .merge(Yaml::file(config_path))
        .merge(Env::prefixed("SENTRY_MIRROR_"))
        .extract()?;

    if args.verbose {
        config.verbose = true;
        config.log_filter = "debug".into();
    }

    Ok(config)
}

pub fn get_version() -> &'static str {
    let release_name = fs::read_to_string("./VERSION").expect("Unable to read version");
    Box::leak(release_name.into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbound_config_mult_optional() {
        // Test that multiplier is optional and defaults to 1 when not specified
        let json = r#"{"dsn": "https://key@sentry.io/123", "categories": ["event"]}"#;
        let config: OutboundConfig = serde_json::from_str(json).unwrap();

        match config {
            OutboundConfig::Detailed { dsn, categories, multiplier } => {
                assert_eq!(dsn, "https://key@sentry.io/123");
                assert_eq!(categories, Some(vec!["event".to_string()]));
                assert_eq!(multiplier, 1, "multiply should default to 1 when not specified");
            }
            _ => panic!("Expected Detailed variant"),
        }
    }

    #[test]
    fn test_outbound_config_mult_specified() {
        // Test that multiplier can be explicitly set
        let json = r#"{"dsn": "https://key@sentry.io/123", "categories": [], "multiplier": 5}"#;
        let config: OutboundConfig = serde_json::from_str(json).unwrap();

        match config {
            OutboundConfig::Detailed { dsn, categories: _, multiplier } => {
                assert_eq!(dsn, "https://key@sentry.io/123");
                assert_eq!(multiplier, 5, "multiply should be 5 when explicitly specified");
            }
            _ => panic!("Expected Detailed variant"),
        }
    }

    #[test]
    fn test_outbound_config_only_dsn() {
        // Test that only dsn is required, categories and multiplier are optional
        let json = r#"{"dsn": "https://key@sentry.io/123"}"#;
        let config: OutboundConfig = serde_json::from_str(json).unwrap();

        match config {
            OutboundConfig::Detailed { dsn, categories, multiplier } => {
                assert_eq!(dsn, "https://key@sentry.io/123");
                assert_eq!(categories, None, "categories should be None when not specified");
                assert_eq!(multiplier, 1, "multiply should default to 1");
            }
            _ => panic!("Expected Detailed variant"),
        }
    }
}
