use flate2::read::{DeflateDecoder, GzDecoder};
use hyper::body::Bytes;
use hyper::header::HeaderValue;
use hyper::http::request::Builder as RequestBuilder;
use hyper::http::uri::PathAndQuery;
use hyper::{HeaderMap, Request, Uri};
use log::warn;
use regex::Regex;
use serde_json::Value;
use std::io::prelude::*;

use crate::dsn;

/// Several headers should not be forwarded as they can cause data truncation, or incorrect behavior.
const NO_COPY_HEADERS: [&str; 4] = [
    "host",
    "x-forwarded-for",
    "content-length",
    "content-encoding",
];

/// Copy the relevant parts from `uri` and `headers` into a new request that can be sent
/// to the outbound DSN. This function returns `RequestBuilder` because the body types
/// are tedious to deal with.
pub fn make_outbound_request(
    uri: &Uri,
    headers: &HeaderMap,
    outbound: &dsn::Dsn,
) -> RequestBuilder {
    // Update project id in the path
    let mut new_path = uri.path().to_string();
    let path_parts: Vec<_> = uri.path().split('/').filter(|i| !i.is_empty()).collect();
    if path_parts.len() == 3 && path_parts[0] == "api" {
        let original_projectid = path_parts[1];
        let new_project_id = outbound.project_id.clone();
        new_path = new_path.replace(original_projectid, &new_project_id);
    }
    // Replace public keys in the query string
    let query = match uri.query() {
        Some(value) => replace_public_key(value, outbound),
        None => String::new(),
    };

    let path_query: PathAndQuery = if !query.is_empty() {
        format!("{new_path}?{query}").parse().unwrap()
    } else {
        new_path.parse().unwrap()
    };
    let new_uri = Uri::builder()
        .scheme(outbound.scheme.as_str())
        .authority(outbound.host.clone())
        .path_and_query(path_query)
        .build();

    let mut builder = Request::builder().method("POST").uri(new_uri.unwrap());

    let outbound_headers = builder.headers_mut().unwrap();
    for (key, value) in headers.iter() {
        if NO_COPY_HEADERS.contains(&key.as_str()) {
            continue;
        }
        if key == dsn::AUTHORIZATION_HEADER || key == dsn::SENTRY_X_AUTH_HEADER {
            let updated_value = replace_public_key(value.to_str().unwrap(), outbound);
            outbound_headers.insert(key, updated_value.parse().unwrap());
        } else {
            outbound_headers.insert(key, value.clone());
        }
    }

    builder
}

/// Replace the DSN key if it is found in the first line of the body
/// as per the envelope specs https://develop.sentry.dev/sdk/envelopes/
pub fn replace_envelope_dsn(body: &Bytes, outbound: &dsn::Dsn) -> Option<Bytes> {
    // Split the envelope header off if possible
    let mut body_chunks = body.splitn(2, |&x| x == b'\n');
    let envelope_header = match body_chunks.next() {
        Some(b) => b.to_vec(),
        None => return None,
    };
    // We don't want to copy the entire body to String as
    // replays have blobs in them, and we only need the header.
    let message_header = match String::from_utf8(envelope_header) {
        Ok(h) => h,
        Err(e) => {
            warn!("Could not convert envelope header to String {0}", e);

            return None;
        }
    };
    let mut json_header: Value = match serde_json::from_str(&message_header) {
        Ok(data) => data,
        Err(_) => return None,
    };
    let mut modified = false;
    if json_header.get("dsn").is_some() {
        json_header["dsn"] = Value::String(outbound.to_string());
        modified = true;
    }
    if let Some(trace) = json_header.get("trace") {
        if trace.get("public_key").is_some() {
            json_header["trace"]["public_key"] = Value::String(outbound.public_key.clone());
            modified = true;
        }
    }
    if !modified {
        return None;
    }

    let header_line = Bytes::from(json_header.to_string());
    let envelope_body = match body_chunks.next() {
        Some(c) => c.to_owned(),
        None => return None,
    };
    let new_body =
        Bytes::from([header_line, Bytes::from("\n"), Bytes::from(envelope_body)].concat());

    Some(new_body)
}

fn replace_public_key(target: &str, outbound: &dsn::Dsn) -> String {
    let pattern = Regex::new(r"sentry_key=([a-f0-9]+)").unwrap();
    let public_key = &outbound.public_key;
    let replacement = format!("sentry_key={public_key}");
    let res = pattern.replace(target, replacement);

    res.into_owned()
}

#[derive(Debug)]
pub enum BodyError {
    UnsupportedCodec,
    CouldNotDecode(#[allow(dead_code)] std::io::Error),
    InvalidHeader,
}

/// Decode compressed body into hyper::Bytes
pub fn decode_body(encoding_header: &HeaderValue, body: &Bytes) -> Result<Bytes, BodyError> {
    let encoding_value = match encoding_header.to_str() {
        Ok(value) => value,
        Err(_) => return Err(BodyError::InvalidHeader),
    };
    let mut decompressed = Vec::with_capacity(8 * 1024);
    let body_vec = body.to_vec();

    if encoding_value == "gzip" {
        let mut decoder = GzDecoder::new(body_vec.as_slice());

        decoder
            .read_to_end(&mut decompressed)
            .map_err(BodyError::CouldNotDecode)?;

        Ok(Bytes::from(decompressed))
    } else if encoding_value == "deflate" {
        let mut decoder = DeflateDecoder::new(body_vec.as_slice());

        decoder
            .read_to_end(&mut decompressed)
            .map_err(BodyError::CouldNotDecode)?;

        Ok(Bytes::from(decompressed))
    } else {
        Err(BodyError::UnsupportedCodec)
    }
}

#[cfg(test)]
mod tests {
    use flate2::{
        read::{DeflateEncoder, GzEncoder},
        Compression,
    };

    use super::*;

    #[test]
    fn make_outbound_request_remove_proxy_headers() {
        let outbound: dsn::Dsn = "https://outbound@o123.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/1/envelope/"
            .parse()
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("Origin", "example.com".parse().unwrap());
        headers.insert("Content-Length", "42".parse().unwrap());
        headers.insert("Host", "sentry.example.com".parse().unwrap());
        headers.insert("X-Forwarded-For", "127.0.0.1".parse().unwrap());
        headers.insert("Content-Encoding", "gzip".parse().unwrap());

        let builder = make_outbound_request(&uri, &headers, &outbound);
        let res = builder.body("");

        assert!(res.is_ok());
        let req = res.unwrap();
        let headers = req.headers();
        assert!(!headers.contains_key("Content-Encoding"));
        assert!(!headers.contains_key("Content-Length"));
        assert!(!headers.contains_key("Host"));
        assert!(!headers.contains_key("X-Forwared-For"));
        assert!(headers.contains_key("Origin"));
    }

    #[test]
    fn make_outbound_request_replace_sentry_auth_header() {
        let outbound: dsn::Dsn = "https://outbound@o123.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/1/envelope/"
            .parse()
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("Origin", "example.com".parse().unwrap());
        headers.insert("X-Sentry-Auth", "sentry_key=abcdef".parse().unwrap());

        let builder = make_outbound_request(&uri, &headers, &outbound);
        let res = builder.body("");

        assert!(res.is_ok());
        let req = res.unwrap();
        let header_val = req.headers().get("X-Sentry-Auth").unwrap();
        assert_eq!(header_val, "sentry_key=outbound");
        assert!(req.headers().contains_key("Origin"));
        assert_eq!(req.method(), "POST");
    }

    #[test]
    fn make_outbound_request_replace_authorization_header() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/1/envelope/"
            .parse()
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert(
            "Authorization",
            "sentry_version=7,sentry_key=abcdef".parse().unwrap(),
        );

        let builder = make_outbound_request(&uri, &headers, &outbound);
        let res = builder.body("");

        assert!(res.is_ok());
        let req = res.unwrap();

        let mut header_val = req.headers().get("Authorization").unwrap();
        assert_eq!(header_val, "sentry_version=7,sentry_key=outbound");

        header_val = req.headers().get("Content-Type").unwrap();
        assert_eq!(header_val, "application/json");
        assert_eq!(req.method(), "POST");
    }

    #[test]
    fn make_outbound_request_replace_query_key() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri =
            "https://o123.ingest.sentry.io/api/1/envelope/?sentry_key=abcdef&sentry_version=7"
                .parse()
                .unwrap();

        let headers = HeaderMap::new();
        let builder = make_outbound_request(&uri, &headers, &outbound);
        let res = builder.body("");
        assert!(res.is_ok());
        let req = res.unwrap();

        let uri = req.uri();
        assert_eq!(
            uri,
            "https://o789.ingest.sentry.io/api/6789/envelope/?sentry_key=outbound&sentry_version=7"
        );
    }

    #[test]
    fn make_outbound_request_replace_path_host_and_scheme() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "http://o123.ingest.sentry.io/api/1/envelope/"
            .parse()
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("Host", "o555.ingest.sentry.io".parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert(
            "Authorization",
            "sentry_version=7,sentry_key=abcdef".parse().unwrap(),
        );

        let builder = make_outbound_request(&uri, &headers, &outbound);
        let res = builder.body("");
        assert!(res.is_ok());
        let req = res.unwrap();

        let uri = req.uri();
        assert_eq!(uri, "https://o789.ingest.sentry.io/api/6789/envelope/");
    }

    #[test]
    fn test_replace_envelope_dsn_empty_body() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let body = Bytes::from("");
        let result = replace_envelope_dsn(&body, &outbound);

        assert!(result.is_none());
    }

    #[test]
    fn test_replace_envelope_dsn_missing_key() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![r#"{"key":"value"}"#, r#"{"second":"line"}"#];
        let body = string_list_to_bytes(lines);
        let result = replace_envelope_dsn(&body, &outbound);

        assert!(result.is_none());
    }

    #[test]
    fn test_replace_envelope_dsn_only_first_line() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![r#"{"dsn":"value"}"#, r#"{"second":"line", "dsn":"value"}"#];
        let body = string_list_to_bytes(lines);
        let result = replace_envelope_dsn(&body, &outbound);

        assert!(result.is_some());
        let new_body = result.unwrap();
        let expected_lines = vec![
            r#"{"dsn":"https://outbound@o789.ingest.sentry.io/6789"}"#,
            r#"{"second":"line", "dsn":"value"}"#,
        ];
        let expected = string_list_to_bytes(expected_lines);
        assert_eq!(new_body, expected);
    }

    #[test]
    fn test_replace_envelope_dsn_present() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![
            r#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"5cb13bb8-eb7f-4a50-a8d8-9d309fd1049d"}"#,
            r#"{"message":"something failed"}"#,
        ];
        let body = string_list_to_bytes(lines);
        let result = replace_envelope_dsn(&body, &outbound);

        assert!(result.is_some());

        let new_body = result.unwrap();
        assert!(!new_body.is_empty());

        let expected_lines = vec![
            r#"{"dsn":"https://outbound@o789.ingest.sentry.io/6789","event_id":"5cb13bb8-eb7f-4a50-a8d8-9d309fd1049d"}"#,
            r#"{"message":"something failed"}"#,
        ];
        let expected = string_list_to_bytes(expected_lines);
        assert_eq!(new_body, expected);
    }

    #[test]
    fn test_replace_envelope_dsn_trace_public_key() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![
            r#"{"dsn":"http://abcdef@localhost:3000/12345","trace":{"public_key":"abcdef"}}"#,
            r#"{"second":"line", "dsn":"value"}"#,
        ];
        let body = string_list_to_bytes(lines);
        let result = replace_envelope_dsn(&body, &outbound);

        assert!(result.is_some());
        let new_body = result.unwrap();
        let expected_lines = vec![
            r#"{"dsn":"https://outbound@o789.ingest.sentry.io/6789","trace":{"public_key":"outbound"}}"#,
            r#"{"second":"line", "dsn":"value"}"#,
        ];
        let expected = string_list_to_bytes(expected_lines);
        assert_eq!(new_body, expected);
    }

    #[test]
    fn test_decode_body_gzip() {
        let contents = b"some content to be compressed";
        let mut encoder = GzEncoder::new(&contents[..], Compression::fast());
        let mut buffer_out = Vec::new();
        encoder.read_to_end(&mut buffer_out).unwrap();

        let bytes = Bytes::from(buffer_out);
        let header_val: HeaderValue = "gzip".parse().unwrap();
        let res = decode_body(&header_val, &bytes);
        assert!(res.is_ok());
        let decoded = res.unwrap();

        assert_eq!(
            decoded.to_vec().as_slice(),
            contents,
            "should get the same data back"
        );
    }

    #[test]
    fn test_decode_body_deflate() {
        let contents = b"some content to be compressed";
        let mut encoder = DeflateEncoder::new(&contents[..], Compression::fast());
        let mut buffer_out = Vec::new();
        encoder.read_to_end(&mut buffer_out).unwrap();

        let bytes = Bytes::from(buffer_out);
        let header_val: HeaderValue = "deflate".parse().unwrap();
        let res = decode_body(&header_val, &bytes);
        assert!(res.is_ok());
        let decoded = res.unwrap();

        assert_eq!(
            decoded.to_vec().as_slice(),
            contents,
            "should get the same data back"
        );
    }

    #[test]
    fn test_decode_body_error() {
        let contents = "some content to be compressed";
        let bytes = Bytes::from(contents);
        let header_val: HeaderValue = "deflate".parse().unwrap();
        let res = decode_body(&header_val, &bytes);
        assert!(res.is_err());
    }

    fn string_list_to_bytes(lines: Vec<&str>) -> Bytes {
        let joined = lines.join("\n");

        Bytes::from(joined)
    }
}
