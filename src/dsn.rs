use std::collections::HashMap;
use std::fmt;
use std::str;
use std::str::FromStr;

use hyper::{HeaderMap, Uri};
use regex::Regex;
use url::Url;

use crate::config;

/// DSN components parsed from a DSN string
#[derive(Debug, Clone, PartialEq)]
pub struct Dsn {
    /// The public key for a DSN. Public keys should be unique.
    pub public_key: String,
    /// Mostly unused, can show up in older DSNs
    pub secret_key: String,
    /// The sentry project ths DSN belongs to.
    pub project_id: String,
    /// The DSN host, can either be an upstream or the local server instance.
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
        let project_id = &self.project_id;
        write!(f, "{scheme}://{public_key}@{host}/{project_id}")
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
        let host = match url.host_str() {
            Some(h) => h.to_string(),
            None => return Err(DsnParseError::MissingHost),
        };
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

#[derive(Debug, PartialEq)]
pub struct DsnKeyRing {
    pub inbound: Dsn,
    pub outbound: Vec<Dsn>,
}

/// Convert a list of Config data keys into Dsn's that we can use
/// when handling requests.
pub fn make_key_map(keys: Vec<config::KeyRing>) -> HashMap<String, DsnKeyRing> {
    let mut keymap: HashMap<String, DsnKeyRing> = HashMap::new();
    for item in keys {
        let inbound_dsn = match item.inbound.expect("Missing inbound key").parse::<Dsn>() {
            Ok(r) => r,
            Err(e) => panic!("{:?}", e),
        };
        let outbound = item
            .outbound
            .iter()
            .filter_map(|item| match item {
                Some(i) => Some(i),
                None => None,
            })
            .map(|outbound_str| outbound_str.parse::<Dsn>().expect("Invalid outbound DSN"))
            .collect::<Vec<Dsn>>();
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
    use crate::config::KeyRing;

    #[test]
    fn parse_from_string_valid() {
        let dsn: Dsn = "http://390bf7f953b7492c9007d2cf69078adf@localhost:8765/1847101"
            .parse()
            .unwrap();
        assert_eq!("390bf7f953b7492c9007d2cf69078adf", dsn.public_key);
        assert_eq!("localhost", dsn.host);
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
    fn make_key_map_valid() {
        let keys = vec![KeyRing {
            inbound: Some("https://abcdef@sentry.io/1234".to_string()),
            outbound: vec![
                Some("https://ghijkl@sentry.io/567".to_string()),
                Some("https://mnopq@sentry.io/890".to_string()),
            ],
        }];
        let keymap = make_key_map(keys);
        assert_eq!(keymap.len(), 1);
        let value = keymap.get("abcdef").expect("Should have a value");
        assert_eq!(value.inbound.public_key, "abcdef");
        assert_eq!(value.outbound.len(), 2);
        assert_eq!(value.outbound[0].public_key, "ghijkl");
        assert_eq!(value.outbound[1].public_key, "mnopq");
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
    fn test_dsn_configuration_logging_format() {
        // Test that we can format DSN configuration info for logging
        let keys = vec![
            KeyRing {
                inbound: Some("https://abcdef123456789012345678901234@localhost:8765/1234".to_string()),
                outbound: vec![
                    Some("https://outbound123456789012345678901@sentry.io/5678".to_string()),
                    Some("https://outbound234567890123456789012@other.io/9012".to_string()),
                ],
            },
            KeyRing {
                inbound: Some("https://xyz789012345678901234567890123@localhost:8765/3456".to_string()),
                outbound: vec![
                    Some("https://target12345678901234567890123@target.io/7890".to_string()),
                ],
            },
        ];

        let keymap = make_key_map(keys);

        // Verify the keymap structure that will be logged
        assert_eq!(keymap.len(), 2);

        // Verify we can format the outbound info as expected in the logs
        for (inbound_key, keyring) in keymap.iter() {
            let outbound_info: Vec<String> = keyring
                .outbound
                .iter()
                .map(|dsn| format!("{} ({})", dsn.host, dsn.public_key))
                .collect();

            let formatted = format!("Inbound key: {} -> Outbound: [{}]", inbound_key, outbound_info.join(", "));

            // Verify the format contains expected components
            assert!(formatted.contains("Inbound key:"));
            assert!(formatted.contains("Outbound:"));
            assert!(formatted.contains(inbound_key));
        }
    }

    #[test]
    fn test_dsn_configuration_logging_single_outbound() {
        // Test logging format with single outbound DSN
        let keys = vec![KeyRing {
            inbound: Some("https://single123456789012345678901234@localhost:8765/111".to_string()),
            outbound: vec![
                Some("https://target123456789012345678901234@sentry.io/222".to_string()),
            ],
        }];

        let keymap = make_key_map(keys);
        let (_inbound_key, keyring) = keymap.iter().next().unwrap();

        let outbound_info: Vec<String> = keyring
            .outbound
            .iter()
            .map(|dsn| format!("{} ({})", dsn.host, dsn.public_key))
            .collect();

        assert_eq!(outbound_info.len(), 1);
        assert!(outbound_info[0].contains("sentry.io"));
        assert!(outbound_info[0].contains("target123456789012345678901234"));
    }

    #[test]
    fn test_dsn_configuration_logging_multiple_outbound() {
        // Test logging format with multiple outbound DSNs
        let keys = vec![KeyRing {
            inbound: Some("https://multi1234567890123456789012345@localhost:8765/333".to_string()),
            outbound: vec![
                Some("https://out1123456789012345678901234@host1.io/444".to_string()),
                Some("https://out2123456789012345678901234@host2.io/555".to_string()),
                Some("https://out3123456789012345678901234@host3.io/666".to_string()),
            ],
        }];

        let keymap = make_key_map(keys);
        let (_, keyring) = keymap.iter().next().unwrap();

        let outbound_info: Vec<String> = keyring
            .outbound
            .iter()
            .map(|dsn| format!("{} ({})", dsn.host, dsn.public_key))
            .collect();

        assert_eq!(outbound_info.len(), 3);

        // Verify joined format
        let joined = outbound_info.join(", ");
        assert!(joined.contains("host1.io"));
        assert!(joined.contains("host2.io"));
        assert!(joined.contains("host3.io"));
        assert!(joined.contains(", "));
    }
}
