use std::collections::HashMap;
use std::str;

use hyper::{HeaderMap, Uri};
use regex::Regex;
use url::Url;

use crate::config;

/// DSN components parsed from a DSN string
#[derive(Debug, Clone, PartialEq)]
pub struct Dsn {
    pub public_key: String,
    pub secret_key: String,
    pub project_id: String,
    pub host: String,
    pub path: String,
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
    pub fn from_string(input: String) -> Result<Self, DsnParseError> {
        let url = match Url::parse(&input) {
            Ok(u) => u,
            Err(_) => return Err(DsnParseError::InvalidUrl),
        };
        if url.username().len() < 1 {
            return Err(DsnParseError::MissingPublicKey);
        }
        let public_key = url.username().to_string();
        let secret_key = match url.password() {
            Some(v) => v.to_string(),
            None => "".to_string(),
        };
        let host = match url.host_str() {
            Some(h) => h.to_string(),
            None => return Err(DsnParseError::MissingHost),
        };
        let path = url.path().to_string();
        let path_segments = match url.path_segments() {
            Some(s) => s,
            None => return Err(DsnParseError::MissingPath),

        };
        let project_id = match path_segments.last() {
            Some(p) => p.to_string(),
            None => return Err(DsnParseError::MissingProjectId),
        };
        if project_id == "/" || project_id == "" {
            return Err(DsnParseError::MissingProjectId);
        }

        Ok(Dsn {
            public_key,
            secret_key,
            project_id,
            host,
            path,
        })
    }

    /// Get a string of the key's identity.
    pub fn key_id(&self) -> String {
        return self.public_key.to_string()
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
        let inbound_dsn = match Dsn::from_string(item.inbound.expect("Missing inbound key")) {
            Ok(r) => r,
            Err(e) => panic!("{:?}", e),
        };
        let outbound = item.outbound.iter()
            .filter_map(|item| match item {
                Some(i) => Some(i),
                None => None,
            })
            .map(|outbound_str| {
                return Dsn::from_string(outbound_str.to_owned()).expect("Invalid outbound DSN")
            }).collect::<Vec<Dsn>>();
        keymap.insert(inbound_dsn.key_id(), DsnKeyRing {
            inbound: inbound_dsn,
            outbound,
        });
    }
    keymap
}

const SENTRY_X_AUTH_HEADER: &str = "X-Sentry-Auth";
const AUTHORIZATION_HEADER: &str = "Authorization";

/// Find and extract a DSN from an incoming request.
pub fn from_request(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    let mut key_source = String::new();

    // Check the request query if it has one
    let query = match uri.query() {
        Some(v) => v,
        None => "",
    };
    if query.len() > 0 {
        key_source = query.to_string();
    }
    // Check the X-Sentry-Auth header and Authorization Header
    if key_source.len() == 0 {
        for key in [SENTRY_X_AUTH_HEADER, AUTHORIZATION_HEADER] {
            if let Some(header) = headers.get(key) {
                key_source = String::from_utf8(header.as_bytes().to_vec()).unwrap();
                break;
            }
        }
    }

    if key_source.len() > 0 {
        let pattern = Regex::new(r"sentry_key=([a-f0-9]{32})").unwrap();
        let capture = match pattern.captures(&key_source) {
            Some(v) => v,
            None => return None,
        };

        return Some(capture[1].to_string());
    }
    return None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeyRing;

    #[test]
    fn parse_from_string_valid() {
        let dsn = Dsn::from_string("http://390bf7f953b7492c9007d2cf69078adf@localhost:8765/1847101".to_string()).unwrap();
        assert_eq!("390bf7f953b7492c9007d2cf69078adf", dsn.public_key);
        assert_eq!("localhost", dsn.host);
        assert_eq!("1847101", dsn.project_id);
    }

    #[test]
    fn parse_from_string_orgdomain() {
        let dsn_str = "https://d2030950946a6197f9cdb9633c069eea@o4507063958255996.ingest.de.sentry.io/4501063980026892";
        let dsn = Dsn::from_string(dsn_str.to_string()).unwrap();
        assert_eq!("d2030950946a6197f9cdb9633c069eea", dsn.public_key);
        assert_eq!("o4507063958255996.ingest.de.sentry.io", dsn.host);
        assert_eq!("4501063980026892", dsn.project_id);
        assert_eq!("", dsn.secret_key);
    }

    #[test]
    fn parse_from_string_missing_project_id() {
        let dsn_str = "https://abcdef@sentry.internal";
        let dsn = Dsn::from_string(dsn_str.to_string());
        assert_eq!(true, dsn.is_err());
    }

    #[test]
    fn parse_from_string_missing_empty_string() {
        let dsn_str = "";
        let dsn = Dsn::from_string(dsn_str.to_string());
        assert_eq!(true, dsn.is_err());
    }

    #[test]
    fn make_key_map_valid() {
        let keys = vec![
            KeyRing {
                inbound: Some("https://abcdef@sentry.io/1234".to_string()),
                outbound: vec![
                    Some("https://ghijkl@sentry.io/567".to_string()),
                    Some("https://mnopq@sentry.io/890".to_string())
                ]
            }
        ];
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
        let uri = format!("https://ingest.sentry.io/api/123/envelope?sentry_key={needle}&other=value").parse::<Uri>().unwrap();
        let headers = HeaderMap::new();

        let res = from_request(&uri, &headers);
        assert_eq!(res.is_some(), true);
        assert_eq!(res.unwrap(), needle);
    }

    #[test]
    fn from_request_header_query_string_not_found() {
        // Key is missing 2 chars
        let needle = "f".repeat(30);
        let uri = format!("https://ingest.sentry.io/api/123/envelope?sentry_key={needle}&other=value").parse::<Uri>().unwrap();
        let headers = HeaderMap::new();

        let res = from_request(&uri, &headers);
        assert_eq!(res.is_none(), true);
    }

    #[test]
    fn from_request_header_sentry_auth() {
        let needle = "af".repeat(16);
        let uri = "https://ingest.sentry.io/api/123/envelope".parse::<Uri>().unwrap();
        let mut headers = HeaderMap::new();
        let header_val = format!("sentry_key={needle}");
        headers.insert("X-Sentry-Auth", header_val.parse().unwrap());

        let res = from_request(&uri, &headers);
        assert_eq!(res.is_some(), true);
        assert_eq!(res.unwrap(), needle);
    }

    #[test]
    fn from_request_header_sentry_auth_not_found() {
        let uri = "https://ingest.sentry.io/api/123/envelope".parse::<Uri>().unwrap();
        let mut headers = HeaderMap::new();
        let header_val = "sentry_key=derpity-derp";
        headers.insert("X-Sentry-Auth", header_val.parse().unwrap());

        let res = from_request(&uri, &headers);
        assert_eq!(res.is_some(), false);
    }

    #[test]
    fn from_request_header_authorization() {
        let needle = "af".repeat(16);
        let uri = "https://ingest.sentry.io/api/123/envelope".parse::<Uri>().unwrap();
        let mut headers = HeaderMap::new();
        let header_val = format!("sentry_key={needle}");
        headers.insert("Authorization", header_val.parse().unwrap());

        let res = from_request(&uri, &headers);
        assert_eq!(res.is_some(), true);
        assert_eq!(res.unwrap(), needle);
    }

    #[test]
    fn from_request_header_authorization_not_found() {
        let uri = "https://ingest.sentry.io/api/123/envelope".parse::<Uri>().unwrap();
        let mut headers = HeaderMap::new();
        let header_val = "sentry_key=derpity-derp";
        headers.insert("Authorization", header_val.parse().unwrap());

        let res = from_request(&uri, &headers);
        assert_eq!(res.is_some(), false);
    }
}
