use std::collections::HashMap;
use std::fmt;
use std::str;
use std::str::FromStr;

use hyper::{HeaderMap, Uri};
use regex::Regex;
use tracing::{error, warn};
use url::Url;

use crate::config::{ConfigData, OutboundConfig};
use crate::sampling::{self, SampleRates};

/// DSN components parsed from a DSN string
#[derive(Debug, Clone, PartialEq)]
pub struct Dsn {
    /// The public key for a DSN. Public keys should be unique.
    pub public_key: String,
    /// Mostly unused, can show up in older DSNs
    pub secret_key: String,
    /// The sentry project ths DSN belongs to.
    pub project_id: String,
    /// The DSN host & port, can either be an upstream or the local server instance.
    pub host: String,
    /// The path components for the DSN. Generally just the project id.
    pub path: String,
    /// https/http
    pub scheme: String,
}

#[derive(Debug)]
pub enum DsnParseError {
    MissingPublicKey,
    MissingHost,
    MissingPath,
    MissingProjectId,
    InvalidUrl,
}

impl Dsn {
    /// Get a string of the key's identity.
    pub fn key_id(&self) -> String {
        self.public_key.to_string()
    }
}

impl fmt::Display for Dsn {
    /// Get the string representation of a DSN
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let scheme = &self.scheme;
        let public_key = &self.public_key;
        let host = &self.host;
        let path = &self.path;
        write!(f, "{scheme}://{public_key}@{host}{path}")
    }
}

impl FromStr for Dsn {
    type Err = DsnParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let url = match Url::parse(input) {
            Ok(u) => u,
            Err(_) => return Err(DsnParseError::InvalidUrl),
        };
        if url.username().is_empty() {
            return Err(DsnParseError::MissingPublicKey);
        }
        let public_key = url.username().to_string();
        let secret_key = match url.password() {
            Some(v) => v.to_string(),
            None => "".to_string(),
        };
        let scheme = url.scheme().to_string();
        let mut host = match url.host() {
            Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
            Some(h) => h.to_string(),
            None => return Err(DsnParseError::MissingHost),
        };
        if let Some(port) = url.port() {
            host = format!("{host}:{port}");
        }

        let path = url.path().to_string();
        let mut path_segments = match url.path_segments() {
            Some(s) => s,
            None => return Err(DsnParseError::MissingPath),
        };
        let project_id = match path_segments.next_back() {
            Some(p) => p.to_string(),
            None => return Err(DsnParseError::MissingProjectId),
        };
        if project_id == "/" || project_id.is_empty() {
            return Err(DsnParseError::MissingProjectId);
        }

        Ok(Dsn {
            public_key,
            secret_key,
            project_id,
            host,
            path,
            scheme,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct OutboundEntry {
    pub dsn: Dsn,
    pub categories: Vec<String>,
    pub multiplier: usize,

    /// Sampling rates applied to traffic sent to this DSN.
    /// `None` when the DSN is not sampled.
    pub sample_rate: Option<SampleRates>,
}

#[derive(Debug, PartialEq)]
pub struct DsnKeyRing {
    pub inbound: Dsn,
    pub outbound: Vec<OutboundEntry>,
}

fn parse_outbound(dsn: &str) -> Dsn {
    dsn.parse::<Dsn>().expect("Invalid outbound DSN")
}

/// Convert a list of Config data keys into Dsn's that we can use
/// when handling requests.
pub fn make_key_map(config: &ConfigData) -> HashMap<String, DsnKeyRing> {
    let mut keymap: HashMap<String, DsnKeyRing> = HashMap::new();

    for item in &config.keys {
        let inbound_dsn = match item.inbound.parse::<Dsn>() {
            Ok(r) => r,
            Err(e) => panic!("{:?}", e),
        };
        let outbound = item
            .outbound
            .iter()
            .filter_map(|item| match item {
                OutboundConfig::Dsn(opt) => opt.as_ref().map(|dsn_str| OutboundEntry {
                    dsn: parse_outbound(dsn_str),
                    categories: vec![],
                    multiplier: 1,
                    sample_rate: None,
                }),
                OutboundConfig::Detailed {
                    dsn,
                    categories,
                    multiplier,
                    sample_rate,
                } => {
                    let mut problems = Vec::new();
                    let sample_rate = sample_rate
                        .as_ref()
                        .map(|config| sampling::normalize(config, &mut problems));
                    for problem in problems {
                        warn!("Outbound DSN {dsn}: {problem}");
                    }
                    let multiplier = if sample_rate.is_some() && *multiplier > 1 {
                        error!(
                            "Outbound DSN {dsn}: multiplier cannot be combined with sample_rate, ignoring multiplier {multiplier}"
                        );
                        1
                    } else {
                        *multiplier
                    };

                    Some(OutboundEntry {
                        dsn: parse_outbound(dsn),
                        categories: categories.clone().unwrap_or_default(),
                        multiplier,
                        sample_rate,
                    })
                }
            })
            .collect::<Vec<OutboundEntry>>();
        keymap.insert(
            inbound_dsn.key_id(),
            DsnKeyRing {
                inbound: inbound_dsn,
                outbound,
            },
        );
    }

    keymap
}

pub fn format_key_map(keymap: &HashMap<String, DsnKeyRing>) -> String {
    let mut out = String::new();
    for keyring in keymap.values() {
        out.push_str(format!("Inbound: {}\n", keyring.inbound).as_ref());
        out.push_str("Outbound:\n");
        for outbound in keyring.outbound.iter() {
            out.push_str(format!("- {}\n", outbound.dsn).as_ref());
            if !outbound.categories.is_empty() {
                out.push_str(format!("  categories: {:?}\n", outbound.categories).as_ref());
            }
            if let Some(sample_rate) = &outbound.sample_rate {
                out.push_str(format!("  sample_rate: {sample_rate}\n").as_ref());
            }
            if outbound.multiplier > 1 {
                out.push_str(format!("  multiplier: {}\n", outbound.multiplier).as_ref());
            }
        }
    }
    out
}

pub const SENTRY_X_AUTH_HEADER: &str = "X-Sentry-Auth";
pub const AUTHORIZATION_HEADER: &str = "Authorization";
pub const AUTH_HEADERS: [&str; 2] = [SENTRY_X_AUTH_HEADER, AUTHORIZATION_HEADER];

/// Find and extract a DSN from an incoming request.
pub fn from_request(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    let mut key_source = String::new();

    // Check the request query if it has one
    let query = uri.query().unwrap_or("");
    if !query.is_empty() {
        key_source = query.to_string();
    }
    // Check the X-Sentry-Auth header and Authorization Header
    if key_source.is_empty() {
        for key in AUTH_HEADERS {
            if let Some(header) = headers.get(key) {
                key_source = String::from_utf8(header.as_bytes().to_vec()).unwrap();
                break;
            }
        }
    }

    if !key_source.is_empty() {
        let pattern = Regex::new(r"sentry_key=([a-f0-9]{32})").unwrap();
        let capture = pattern.captures(&key_source)?;

        return Some(capture[1].to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigData, ConfigKeyPair, OutboundConfig, SampleRateConfig};
    use crate::logging::LogFormat;
    use std::collections::BTreeMap;

    fn make_test_config() -> ConfigData {
        ConfigData {
            sentry_dsn: None,
            sentry_env: None,
            traces_sample_rate: None,
            log_filter: "debug".into(),
            log_format: LogFormat::Text,
            statsd_addr: None,
            default_metrics_tags: None,
            ip: "127.0.0.1".into(),
            port: 3000,
            verbose: true,
            keys: vec![],
        }
    }

    #[test]
    fn parse_from_string_valid() {
        let dsn: Dsn = "http://390bf7f953b7492c9007d2cf69078adf@localhost:8765/1847101"
            .parse()
            .unwrap();
        assert_eq!("390bf7f953b7492c9007d2cf69078adf", dsn.public_key);
        assert_eq!("localhost:8765", dsn.host);
        assert_eq!("1847101", dsn.project_id);
        assert_eq!(
            "http://390bf7f953b7492c9007d2cf69078adf@localhost:8765/1847101",
            dsn.to_string()
        );
    }

    #[test]
    fn parse_from_string_with_port() {
        let dsn: Dsn = "http://public-key@relay:3001/123456".parse().unwrap();
        assert_eq!("public-key", dsn.public_key);
        assert_eq!("relay:3001", dsn.host);
        assert_eq!("123456", dsn.project_id);
        assert_eq!("http://public-key@relay:3001/123456", dsn.to_string());
    }

    #[test]
    fn parse_from_string_ipv6() {
        let dsn: Dsn = "http://390bf7f953b7492c9007d2cf69078adf@[::1]:8765/1847101"
            .parse()
            .unwrap();
        assert_eq!("390bf7f953b7492c9007d2cf69078adf", dsn.public_key);
        assert_eq!("[::1]:8765", dsn.host);
        assert_eq!("1847101", dsn.project_id);
    }

    #[test]
    fn parse_from_string_orgdomain() {
        let dsn: Dsn = "https://d2030950946a6197f9cdb9633c069eea@o4507063958255996.ingest.de.sentry.io/4501063980026892".parse().unwrap();
        assert_eq!("d2030950946a6197f9cdb9633c069eea", dsn.public_key);
        assert_eq!("o4507063958255996.ingest.de.sentry.io", dsn.host);
        assert_eq!("4501063980026892", dsn.project_id);
        assert_eq!("", dsn.secret_key);
    }

    #[test]
    fn parse_from_string_missing_project_id() {
        let dsn = "https://abcdef@sentry.internal".parse::<Dsn>();
        assert!(dsn.is_err());
    }

    #[test]
    fn parse_from_string_missing_empty_string() {
        let dsn = "".parse::<Dsn>();
        assert!(dsn.is_err());
    }

    #[test]
    fn make_key_map_with_key_rings_only() {
        let mut config = make_test_config();
        config.keys = vec![ConfigKeyPair {
            inbound: "https://abcdef@sentry.io/1234".to_string(),
            outbound: vec![
                OutboundConfig::Dsn(Some("https://ghijkl@sentry.io/567".to_string())),
                OutboundConfig::Dsn(Some("https://mnopq@sentry.io/890".to_string())),
            ],
        }];
        let keymap = make_key_map(&config);
        assert_eq!(keymap.len(), 1);
        let value = keymap.get("abcdef").expect("Should have a value");
        assert_eq!(value.inbound.public_key, "abcdef");
        assert_eq!(value.outbound.len(), 2);
        assert_eq!(value.outbound[0].dsn.public_key, "ghijkl");
        assert_eq!(
            value.outbound[0].categories.len(),
            0,
            "ConfigKeyPair should have no categories"
        );
        assert_eq!(value.outbound[1].dsn.public_key, "mnopq");
        assert_eq!(
            value.outbound[1].categories.len(),
            0,
            "ConfigKeyPair should have no categories"
        );
    }

    #[test]
    fn make_key_map_preserves_custom_ports() {
        let mut config = make_test_config();
        config.keys = vec![ConfigKeyPair {
            inbound: "http://390bf7f953b7492c9007d2cf69078adf@localhost:3001/456".to_string(),
            outbound: vec![
                OutboundConfig::Dsn(Some(
                    "http://4c9330937fda0a7054e0628df7811e74@localhost:3001/4510448567582800"
                        .to_string(),
                )),
                OutboundConfig::Dsn(Some(
                    "http://5d0441a48bea1b8065f1729fe8922f95@relay:3002/9876".to_string(),
                )),
            ],
        }];

        let keymap = make_key_map(&config);
        assert_eq!(keymap.len(), 1);
        let value = keymap
            .get("390bf7f953b7492c9007d2cf69078adf")
            .expect("Should have a value");

        // Verify inbound DSN preserves port
        assert_eq!(value.inbound.host, "localhost:3001");
        assert_eq!(value.inbound.project_id, "456");

        // Verify outbound DSNs preserve ports
        assert_eq!(value.outbound.len(), 2);
        assert_eq!(value.outbound[0].dsn.host, "localhost:3001");
        assert_eq!(value.outbound[0].dsn.project_id, "4510448567582800");
        assert_eq!(value.outbound[1].dsn.host, "relay:3002");
        assert_eq!(value.outbound[1].dsn.project_id, "9876");
    }

    #[test]
    fn make_key_map_with_detailed_outbound() {
        let mut config = make_test_config();
        config.keys = vec![ConfigKeyPair {
            inbound: "https://abcdef@sentry.io/1234".to_string(),
            outbound: vec![
                OutboundConfig::Detailed {
                    dsn: "https://ghijkl@sentry.io/567".to_string(),
                    categories: Some(vec!["event".to_string(), "transaction".to_string()]),
                    multiplier: 1,
                    sample_rate: None,
                },
                OutboundConfig::Detailed {
                    dsn: "https://mnopq@sentry.io/890".to_string(),
                    categories: Some(vec!["replay".to_string()]),
                    multiplier: 1,
                    sample_rate: None,
                },
            ],
        }];
        let keymap = make_key_map(&config);
        assert_eq!(keymap.len(), 1);
        let value = keymap.get("abcdef").expect("Should have a value");
        assert_eq!(value.inbound.public_key, "abcdef");
        assert_eq!(value.outbound.len(), 2);
        assert_eq!(value.outbound[0].dsn.public_key, "ghijkl");
        assert_eq!(value.outbound[0].categories, vec!["event", "transaction"]);
        assert_eq!(value.outbound[1].dsn.public_key, "mnopq");
        assert_eq!(value.outbound[1].categories, vec!["replay"]);
    }

    #[test]
    fn make_key_map_with_mixed_outbound() {
        let mut config = make_test_config();
        config.keys = vec![ConfigKeyPair {
            inbound: "https://key111@sentry.io/1111".to_string(),
            outbound: vec![
                OutboundConfig::Dsn(Some("https://key222@sentry.io/2222".to_string())),
                OutboundConfig::Detailed {
                    dsn: "https://key333@sentry.io/3333".to_string(),
                    categories: Some(vec!["error".to_string(), "span".to_string()]),
                    multiplier: 1,
                    sample_rate: None,
                },
            ],
        }];
        let keymap = make_key_map(&config);

        // Check Dsn entry
        let key_value = keymap
            .get("key111")
            .expect("Should have ConfigKeyPair entry");
        assert_eq!(key_value.inbound.public_key, "key111");
        assert_eq!(key_value.outbound.len(), 2);
        assert_eq!(key_value.outbound[0].dsn.public_key, "key222");
        assert_eq!(key_value.outbound[0].categories.len(), 0);
        assert_eq!(key_value.outbound[1].dsn.public_key, "key333");
        assert_eq!(key_value.outbound[1].categories, vec!["error", "span"]);
    }

    /// Build a keymap with a single detailed outbound DSN.
    fn key_map_with(multiplier: usize, sample_rate: Option<SampleRateConfig>) -> DsnKeyRing {
        let mut config = make_test_config();
        config.keys = vec![ConfigKeyPair {
            inbound: "https://abcdef@sentry.io/1234".to_string(),
            outbound: vec![OutboundConfig::Detailed {
                dsn: "https://ghijkl@sentry.io/567".to_string(),
                categories: None,
                multiplier,
                sample_rate,
            }],
        }];
        let mut keymap = make_key_map(&config);

        keymap.remove("abcdef").expect("Should have a value")
    }

    #[test]
    fn make_key_map_with_sample_rate_float() {
        let keyring = key_map_with(1, Some(SampleRateConfig::Uniform(0.5)));
        let rates = keyring.outbound[0]
            .sample_rate
            .as_ref()
            .expect("should have rates");

        assert_eq!(rates.rate_for("error"), 0.5);
        assert_eq!(rates.rate_for("span"), 0.5);
    }

    #[test]
    fn make_key_map_with_sample_rate_map() {
        let rates = BTreeMap::from([("span".to_string(), 0.05)]);
        let keyring = key_map_with(1, Some(SampleRateConfig::PerCategory(rates)));
        let rates = keyring.outbound[0]
            .sample_rate
            .as_ref()
            .expect("should have rates");

        assert_eq!(rates.rate_for("span"), 0.05);
        assert_eq!(
            rates.rate_for("error"),
            1.0,
            "unlisted categories are not sampled"
        );
    }

    #[test]
    fn make_key_map_no_sample_rate() {
        let keyring = key_map_with(1, None);

        assert_eq!(keyring.outbound[0].sample_rate, None);
    }

    #[test]
    fn make_key_map_clamps_out_of_range_sample_rate() {
        let keyring = key_map_with(1, Some(SampleRateConfig::Uniform(2.0)));
        let rates = keyring.outbound[0]
            .sample_rate
            .as_ref()
            .expect("should have rates");

        assert_eq!(rates.rate_for("error"), 1.0);
    }

    #[test]
    fn make_key_map_sample_rate_and_multiplier_conflict() {
        let keyring = key_map_with(4, Some(SampleRateConfig::Uniform(0.5)));

        assert_eq!(
            keyring.outbound[0].multiplier, 1,
            "multiplier should be ignored when sampling"
        );
        assert!(keyring.outbound[0].sample_rate.is_some());
    }

    #[test]
    fn make_key_map_multiplier_without_sample_rate_preserved() {
        let keyring = key_map_with(4, None);

        assert_eq!(keyring.outbound[0].multiplier, 4);
    }

    #[test]
    fn from_request_header_query_string() {
        let needle = "f".repeat(32);
        let uri =
            format!("https://ingest.sentry.io/api/123/envelope?sentry_key={needle}&other=value")
                .parse::<Uri>()
                .unwrap();
        let headers = HeaderMap::new();

        let res = from_request(&uri, &headers);
        assert!(res.is_some());
        assert_eq!(res.unwrap(), needle);
    }

    #[test]
    fn from_request_header_query_string_not_found() {
        // Key is missing 2 chars
        let needle = "f".repeat(30);
        let uri =
            format!("https://ingest.sentry.io/api/123/envelope?sentry_key={needle}&other=value")
                .parse::<Uri>()
                .unwrap();
        let headers = HeaderMap::new();

        let res = from_request(&uri, &headers);
        assert!(res.is_none());
    }

    #[test]
    fn from_request_header_sentry_auth() {
        let needle = "af".repeat(16);
        let uri = "https://ingest.sentry.io/api/123/envelope"
            .parse::<Uri>()
            .unwrap();
        let mut headers = HeaderMap::new();
        let header_val = format!("sentry_key={needle}");
        headers.insert("X-Sentry-Auth", header_val.parse().unwrap());

        let res = from_request(&uri, &headers);
        assert!(res.is_some());
        assert_eq!(res.unwrap(), needle);
    }

    #[test]
    fn from_request_header_sentry_auth_not_found() {
        let uri = "https://ingest.sentry.io/api/123/envelope"
            .parse::<Uri>()
            .unwrap();
        let mut headers = HeaderMap::new();
        let header_val = "sentry_key=derpity-derp";
        headers.insert("X-Sentry-Auth", header_val.parse().unwrap());

        let res = from_request(&uri, &headers);
        assert!(res.is_none());
    }

    #[test]
    fn from_request_header_authorization() {
        let needle = "af".repeat(16);
        let uri = "https://ingest.sentry.io/api/123/envelope"
            .parse::<Uri>()
            .unwrap();
        let mut headers = HeaderMap::new();
        let header_val = format!("sentry_key={needle}");
        headers.insert("Authorization", header_val.parse().unwrap());

        let res = from_request(&uri, &headers);
        assert!(res.is_some());
        assert_eq!(res.unwrap(), needle);
    }

    #[test]
    fn from_request_header_authorization_not_found() {
        let uri = "https://ingest.sentry.io/api/123/envelope"
            .parse::<Uri>()
            .unwrap();
        let mut headers = HeaderMap::new();
        let header_val = "sentry_key=derpity-derp";
        headers.insert("Authorization", header_val.parse().unwrap());

        let res = from_request(&uri, &headers);
        assert!(res.is_none());
    }

    #[test]
    fn test_format_key_map() {
        let mut config = make_test_config();
        config.keys = vec![ConfigKeyPair {
            inbound: "https://abcdef@sentry.io/1234".to_string(),
            outbound: vec![
                OutboundConfig::Dsn(Some("https://ghijkl@sentry.io/567".to_string())),
                OutboundConfig::Dsn(Some("https://mnopq@sentry.io/890".to_string())),
            ],
        }];
        let key_map = make_key_map(&config);
        let output = format_key_map(&key_map);
        dbg!(&output);
        assert!(output.contains("Inbound: https://abcdef@sentry.io/1234"));
        assert!(output.contains("Outbound:\n"));
        assert!(output.contains("- https://ghijkl@sentry.io/567\n"));
        assert!(output.contains("- https://mnopq@sentry.io/890\n"));
    }

    #[test]
    fn test_format_key_map_with_sample_rate() {
        let mut config = make_test_config();
        config.keys = vec![ConfigKeyPair {
            inbound: "https://abcdef@sentry.io/1234".to_string(),
            outbound: vec![
                OutboundConfig::Detailed {
                    dsn: "https://ghijkl@sentry.io/567".to_string(),
                    categories: None,
                    multiplier: 1,
                    sample_rate: Some(SampleRateConfig::Uniform(0.5)),
                },
                OutboundConfig::Detailed {
                    dsn: "https://mnopq@sentry.io/890".to_string(),
                    categories: None,
                    multiplier: 1,
                    sample_rate: Some(SampleRateConfig::PerCategory(BTreeMap::from([(
                        "span".to_string(),
                        0.05,
                    )]))),
                },
            ],
        }];
        let key_map = make_key_map(&config);
        let output = format_key_map(&key_map);

        assert!(output.contains("  sample_rate: 0.5\n"), "{output}");
        assert!(
            output.contains("  sample_rate: {span: 0.05} (default 1)\n"),
            "{output}"
        );
    }
}
