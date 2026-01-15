use flate2::read::{DeflateDecoder, GzDecoder};
use http_body_util::BodyExt;
use hyper::body::{Body, Bytes};
use hyper::header::HeaderValue;
use hyper::http::request::Builder as RequestBuilder;
use hyper::http::uri::PathAndQuery;
use hyper::{HeaderMap, Request, Uri};
use regex::Regex;
use serde_json::Value;
use std::io::prelude::*;
use std::time::Instant;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::ConfigData;
use crate::dsn;

/// Several headers should not be forwarded as they can cause data truncation, or incorrect behavior.
const NO_COPY_HEADERS: [&str; 3] = ["host", "x-forwarded-for", "content-length"];
const INGEST_PATH_SEGMENTS: [&str; 4] = ["envelope", "minidump", "store", "integration"];

/// Copy the relevant parts from `uri` and `headers` into a new request that can be sent
/// to the outbound DSN. This function returns `RequestBuilder` because the body types
/// are tedious to deal with.
pub fn make_outbound_request(
    config: &ConfigData,
    uri: &Uri,
    headers: &HeaderMap,
    outbound: &dsn::Dsn,
) -> RequestBuilder {
    // Update project id in the path
    let mut new_path = uri.path().to_string();
    let path_parts: Vec<_> = uri.path().split('/').filter(|i| !i.is_empty()).collect();
    if path_parts.len() >= 3
        && path_parts[0] == "api"
        && INGEST_PATH_SEGMENTS.contains(&path_parts[2])
    {
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
        if NO_COPY_HEADERS.contains(&key.as_str())
            || (config.modify_envelope && key == "content-encoding")
        {
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

fn build_envelope_body(bytes: &[u8], categories: &[String]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(bytes.len());

    // If categories is empty, return copy of all bytes repeated multiplier times
    if categories.is_empty() {
        output.extend_from_slice(bytes);
        return Some(output);
    }

    let mut position = 0;

    // Iterate over blocks in envelope
    while position < bytes.len() {
        // Find the end of the header line (first \n)
        let header_end = match bytes[position..].iter().position(|&x| x == b'\n') {
            Some(pos) => position + pos,
            None => {
                warn!("Could not find header line ending");
                return None;
            }
        };

        let header_slice = &bytes[position..header_end];
        let header_str = match String::from_utf8(header_slice.to_vec()) {
            Ok(h) => h,
            Err(e) => {
                warn!("Could not convert envelope header to String {0}", e);
                return None;
            }
        };

        let header_json: Value = match serde_json::from_str(&header_str) {
            Ok(v) => v,
            Err(e) => {
                warn!("Could not convert envelope header to JSON {0}", e);
                return None;
            }
        };

        let event_type = header_json
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let length = match header_json.get("length").and_then(|v| v.as_u64()) {
            Some(len) => len as usize,
            None => {
                warn!("Missing length field in header for block type {event_type}");
                return None;
            }
        };

        // Move past the header and its \n
        let data_start = header_end + 1;
        let data_end = data_start + length;

        if data_end > bytes.len() {
            warn!("Data length {length} exceeds remaining bytes for block type {event_type}");
            return None;
        }

        let data_chunk = &bytes[data_start..data_end];

        if categories.contains(&event_type.to_string()) {
            output.extend_from_slice(header_slice);
            output.push(b'\n');
            output.extend_from_slice(data_chunk);
            output.push(b'\n');
        }

        // Move to next block (skip past data and the trailing \n)
        position = data_end + 1;
    }
    Some(output)
}

/// Mutate the envelope body based on the outbound key configuration:
///
/// Will do the following:
///
/// - Replace the DSN key in the envelope header with the outbound DSN.
/// - Will filter envelope items based on the categories.
/// - Will multiply matching item types based on multiplier. Each copy
///   will have a unique id generated for it to preserve the projectid + eventid
///   uniqueness constraints
///
/// See the envelope specs https://develop.sentry.dev/sdk/envelopes/
pub fn modify_envelope(
    body: &Bytes,
    outbound: &dsn::Dsn,
    categories: &[String],
    multiplier: usize,
) -> Option<Bytes> {
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
    if let Some(trace) = json_header.get("trace")
        && trace.get("public_key").is_some()
    {
        json_header["trace"]["public_key"] = Value::String(outbound.public_key.clone());
        modified = true;
    }
    if !modified {
        return None;
    }

    let envelope_body_bytes = match body_chunks.next() {
        Some(c) => c,
        None => return None,
    };

    // When multiplier > 1, create multiple complete envelopes, each with a unique event_id
    if multiplier > 1 {
        let mut output = Vec::with_capacity(body.len() * multiplier);

        for _ in 0..multiplier {
            // Generate a unique event_id for each copy, as eventid + project must be unique.
            let new_event_id = Uuid::new_v4().to_string();
            let mut header_copy = json_header.clone();
            header_copy["event_id"] = Value::String(new_event_id);

            let envelope_body = match build_envelope_body(envelope_body_bytes, categories) {
                Some(body) => body,
                None => return None,
            };

            output.extend_from_slice(header_copy.to_string().as_bytes());
            output.push(b'\n');
            output.extend_from_slice(&envelope_body);
        }

        Some(Bytes::from(output))
    } else {
        let header_line = Bytes::from(json_header.to_string());
        let envelope_body = match build_envelope_body(envelope_body_bytes, categories) {
            Some(body) => body,
            None => return None,
        };
        let new_body =
            Bytes::from([header_line, Bytes::from("\n"), Bytes::from(envelope_body)].concat());

        Some(new_body)
    }
}

fn replace_public_key(target: &str, outbound: &dsn::Dsn) -> String {
    let pattern = Regex::new(r"sentry_key=([a-f0-9]+)").unwrap();
    let public_key = &outbound.public_key;
    let replacement = format!("sentry_key={public_key}");
    let res = pattern.replace(target, replacement);

    res.into_owned()
}

pub async fn read_and_decode_body<B: Body>(
    config: &ConfigData,
    request: Request<B>,
    headers: &HeaderMap,
    public_key: &str,
) -> Result<Bytes, String>
where
    B::Error: std::error::Error + Sync + Send + 'static,
{
    let body_read_timer = Instant::now();
    let body_res = request.collect().await;
    if let Err(err) = body_res {
        warn!("Could not read request body {:?}", err);
        return Err("could not read request body".to_string());
    }
    let mut body_bytes = body_res.unwrap().to_bytes();

    metrics::histogram!("handle_proxy.body_read.duration", "inbound_key" => public_key.to_owned())
        .record(body_read_timer.elapsed());
    metrics::histogram!("handle_proxy.body_bytes", "inbound_key" => public_key.to_owned())
        .record(body_bytes.len() as f64);

    if config.verbose {
        let body_str = str::from_utf8(&body_bytes).unwrap_or("<binary data>");
        debug!("Request Body: {}", body_str);
    }

    // Bodies can be compressed. If relay is configured to be more permissive
    // we don't have to decompress and rewrite the body.
    if config.modify_envelope && headers.contains_key("content-encoding") {
        let request_encoding = headers.get("content-encoding").unwrap();
        let decode_body_time = Instant::now();
        body_bytes = match decode_body(request_encoding, &body_bytes) {
            Ok(decompressed) => {
                metrics::histogram!("handle_proxy.decode_body.duration")
                    .record(decode_body_time.elapsed());
                decompressed
            }
            Err(e) => {
                metrics::counter!(
                    "handle_proxy.decode_error",
                    "inbound_key" => public_key.to_owned(),
                )
                .increment(1);
                warn!("Could not decode request body: {0:?}", e);

                return Err("could not decode request body".to_string());
            }
        }
    }

    Ok(body_bytes)
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
    } else if encoding_value == "br" {
        let mut decoder = brotli::Decompressor::new(body_vec.as_slice(), 4096);
        decoder
            .read_to_end(&mut decompressed)
            .map_err(BodyError::CouldNotDecode)?;

        Ok(Bytes::from(decompressed))
    } else if encoding_value == "zstd" {
        match zstd::Decoder::new(body_vec.as_slice()) {
            Ok(mut decoder) => {
                decoder
                    .read_to_end(&mut decompressed)
                    .map_err(BodyError::CouldNotDecode)?;

                Ok(Bytes::from(decompressed))
            }
            Err(err) => {
                warn!("Could not build decoder to read zstd stream {:?}", err);

                Err(BodyError::CouldNotDecode(err))
            }
        }
    } else if encoding_value.is_empty() {
        // Some clients misbehave and send an empty content-encoding value.
        Ok(Bytes::from(body_vec))
    } else {
        warn!(encoding_value, "Unsupported content-encoding header value");
        Err(BodyError::UnsupportedCodec)
    }
}

#[cfg(test)]
mod tests {
    use flate2::{
        Compression,
        read::{DeflateEncoder, GzEncoder},
    };
    use http_body_util::Full;

    use super::*;

    #[test]
    fn make_outbound_request_remove_proxy_headers() {
        let config = ConfigData::default();
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

        let builder = make_outbound_request(&config, &uri, &headers, &outbound);
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
        let config = ConfigData::default();
        let outbound: dsn::Dsn = "https://outbound@o123.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/1/envelope/"
            .parse()
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("Origin", "example.com".parse().unwrap());
        headers.insert("X-Sentry-Auth", "sentry_key=abcdef".parse().unwrap());

        let builder = make_outbound_request(&config, &uri, &headers, &outbound);
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
        let config = ConfigData::default();
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

        let builder = make_outbound_request(&config, &uri, &headers, &outbound);
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
        let config = ConfigData::default();
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri =
            "https://o123.ingest.sentry.io/api/1/envelope/?sentry_key=abcdef&sentry_version=7"
                .parse()
                .unwrap();

        let headers = HeaderMap::new();
        let builder = make_outbound_request(&config, &uri, &headers, &outbound);
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
        let config = ConfigData::default();
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

        let builder = make_outbound_request(&config, &uri, &headers, &outbound);
        let res = builder.body("");
        assert!(res.is_ok());
        let req = res.unwrap();

        let uri = req.uri();
        assert_eq!(uri, "https://o789.ingest.sentry.io/api/6789/envelope/");
    }

    #[test]
    fn make_outbound_request_replace_project_id_oltp_url() {
        let config = ConfigData::default();
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/123/integration/oltp/v1/traces/"
            .parse()
            .unwrap();

        let headers = HeaderMap::new();
        let builder = make_outbound_request(&config, &uri, &headers, &outbound);
        let res = builder.body("");

        assert!(res.is_ok());
        let req = res.unwrap();
        let uri = req.uri();
        assert_eq!(
            uri,
            "https://o789.ingest.sentry.io/api/6789/integration/oltp/v1/traces/"
        );
    }

    #[test]
    fn make_outbound_request_replace_project_id_minidump_url() {
        let config = ConfigData::default();
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/123/minidump/"
            .parse()
            .unwrap();

        let headers = HeaderMap::new();
        let builder = make_outbound_request(&config, &uri, &headers, &outbound);
        let res = builder.body("");

        assert!(res.is_ok());
        let req = res.unwrap();
        let uri = req.uri();
        assert_eq!(uri, "https://o789.ingest.sentry.io/api/6789/minidump/");
    }

    #[test]
    fn make_outbound_request_content_encoding_header() {
        let config = ConfigData::default();
        let outbound: dsn::Dsn = "https://outbound@o123.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/1/envelope/"
            .parse()
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("Origin", "example.com".parse().unwrap());
        headers.insert("X-Sentry-Auth", "sentry_key=abcdef".parse().unwrap());
        headers.insert("Content-Encoding", "br".parse().unwrap());

        let builder = make_outbound_request(&config, &uri, &headers, &outbound);
        let res = builder.body("");

        assert!(res.is_ok());
        let req = res.unwrap();
        assert!(
            !req.headers().contains_key("Content-Encoding"),
            "should be absent when envelope_header modification is on"
        );

        let config = ConfigData {
            modify_envelope: false,
            ..ConfigData::default()
        };
        let builder = make_outbound_request(&config, &uri, &headers, &outbound);
        let res = builder.body("");

        assert!(res.is_ok());
        let req = res.unwrap();
        assert!(
            req.headers().contains_key("Content-Encoding"),
            "should be present when the body is unchanged."
        );
    }

    #[test]
    fn test_modify_envelope_empty_body() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let body = Bytes::from("");
        let result = modify_envelope(&body, &outbound, &[], 1);

        assert!(result.is_none());
    }

    #[test]
    fn test_modify_envelope_missing_key() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![r#"{"key":"value"}"#, r#"{"second":"line"}"#];
        let body = string_list_to_bytes(lines);
        let result = modify_envelope(&body, &outbound, &[], 1);

        assert!(result.is_none());
    }

    #[test]
    fn test_modify_envelope_only_first_line() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![r#"{"dsn":"value"}"#, r#"{"second":"line", "dsn":"value"}"#];
        let body = string_list_to_bytes(lines);
        let result = modify_envelope(&body, &outbound, &[], 1);

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
    fn test_modify_envelope_present() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![
            r#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"5cb13bb8-eb7f-4a50-a8d8-9d309fd1049d"}"#,
            r#"{"message":"something failed"}"#,
        ];
        let body = string_list_to_bytes(lines);
        let result = modify_envelope(&body, &outbound, &[], 1);

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
    fn test_modify_envelope_trace_public_key() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![
            r#"{"dsn":"http://abcdef@localhost:3000/12345","trace":{"public_key":"abcdef"}}"#,
            r#"{"second":"line", "dsn":"value"}"#,
        ];
        let body = string_list_to_bytes(lines);
        let result = modify_envelope(&body, &outbound, &[], 1);

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
    fn test_decode_body_brotli() {
        let contents = b"some content to be compressed";
        let params = brotli::enc::BrotliEncoderParams::default();
        let mut encoder = brotli::CompressorReader::with_params(&contents[..], 4096, &params);
        let mut buffer_out = Vec::new();
        encoder.read_to_end(&mut buffer_out).unwrap();

        let bytes = Bytes::from(buffer_out);
        let header_val: HeaderValue = "br".parse().unwrap();
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
    fn test_decode_body_zstd() {
        let contents = b"some content to be compressed";
        let mut encoder = zstd::stream::read::Encoder::new(&contents[..], 2).unwrap();
        let mut buffer_out = Vec::new();
        encoder.read_to_end(&mut buffer_out).unwrap();

        let bytes = Bytes::from(buffer_out);
        let header_val: HeaderValue = "zstd".parse().unwrap();
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
    fn test_decode_body_empty() {
        let contents = b"some content";
        let bytes = Bytes::from(contents.to_vec());
        let header_val: HeaderValue = "".parse().unwrap();
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

    #[tokio::test]
    async fn test_read_and_decode_body() {
        let config = make_test_config();
        assert!(config.modify_envelope, "Should default to true");

        let contents = b"some content to be compressed";
        let mut encoder = DeflateEncoder::new(&contents[..], Compression::fast());
        let mut buffer_out = Vec::new();
        encoder.read_to_end(&mut buffer_out).unwrap();

        let bytes = Bytes::from(buffer_out);
        let builder = Request::builder()
            .method("POST")
            .header("Content-Encoding", "deflate")
            .uri("http://localhost:3000/store");
        let request = builder.body(Full::new(bytes)).unwrap();
        let headers = request.headers().clone();
        let public_key = "deadbeef".to_string();
        let result = read_and_decode_body(&config, request, &headers, &public_key).await;

        assert!(result.is_ok());
        let new_bytes = result.unwrap();
        assert_eq!(new_bytes.to_vec(), b"some content to be compressed");
    }

    #[tokio::test]
    async fn test_read_and_decode_body_decode_disabled() {
        let mut config = make_test_config();
        config.modify_envelope = false;

        let contents = b"some content to be compressed";
        let mut encoder = DeflateEncoder::new(&contents[..], Compression::fast());
        let mut buffer_out = Vec::new();
        encoder.read_to_end(&mut buffer_out).unwrap();

        let bytes = Bytes::from(buffer_out);
        let expected_bytes = bytes.clone();
        let builder = Request::builder()
            .method("POST")
            .header("Content-Encoding", "deflate")
            .uri("http://localhost:3000/store");
        let request = builder.body(Full::new(bytes)).unwrap();
        let headers = request.headers().clone();
        let public_key = "deadbeef".to_string();
        let result = read_and_decode_body(&config, request, &headers, &public_key).await;

        assert!(result.is_ok());
        let new_bytes = result.unwrap();
        assert_eq!(new_bytes.to_vec(), expected_bytes.to_vec());
        assert_ne!(new_bytes.to_vec(), b"some content to be compressed");
    }

    #[test]
    fn test_build_envelope_body_empty_categories() {
        let mut body = Vec::new();
        body.extend_from_slice(b"{\"type\":\"attachment\",\"length\":5}\n");
        body.extend_from_slice(b"hello");
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");
        body.push(b'\n');

        let categories: Vec<String> = vec![];
        let result = build_envelope_body(&body, &categories);

        assert!(result.is_some(), "Should return Some for valid input");
        assert_eq!(
            result.unwrap(),
            body,
            "Empty categories should return all bytes unchanged"
        );
    }

    #[test]
    fn test_build_envelope_body_with_categories() {
        let mut body = Vec::new();
        body.extend_from_slice(b"{\"type\":\"attachment\",\"length\":5}\n");
        body.extend_from_slice(b"hello");
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");
        body.push(b'\n');

        let categories = vec!["event".to_string()];
        let result = build_envelope_body(&body, &categories);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        expected.extend_from_slice(b"test");
        expected.push(b'\n');

        assert!(result.is_some(), "Should return Some for valid input");
        assert_eq!(
            result.unwrap(),
            expected,
            "Should include filtered block types"
        );
    }

    #[test]
    fn test_build_envelope_body_multiline_data() {
        let mut body = Vec::new();

        let attachment_data = "hello\nhello";
        let attachment_header = format!(
            "{{\"type\":\"attachment\",\"length\":{}}}\n",
            attachment_data.len()
        );

        body.extend_from_slice(attachment_header.as_bytes());
        body.extend_from_slice(attachment_data.as_bytes());
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");
        body.push(b'\n');

        let categories = vec!["attachment".to_string()];
        let result = build_envelope_body(&body, &categories);

        let mut expected = Vec::new();
        expected.extend_from_slice(attachment_header.as_bytes());
        expected.extend_from_slice(attachment_data.as_bytes());
        expected.push(b'\n');

        assert!(result.is_some(), "Should return Some for valid input");
        assert_eq!(
            result.unwrap(),
            expected,
            "Should correctly handle multiline data by using the length field from header"
        );
    }

    #[test]
    fn test_build_envelope_body_binary_data() {
        let mut body = Vec::new();

        let binary_data: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x0A, 0x80, 0x90, 0xA0, 0xB0, 0xC0];
        let binary_header = format!(
            "{{\"type\":\"attachment\",\"length\":{}}}\n",
            binary_data.len()
        );

        body.extend_from_slice(binary_header.as_bytes());
        body.extend_from_slice(&binary_data);
        body.push(b'\n');

        let categories = vec!["attachment".to_string()];
        let result = build_envelope_body(&body, &categories);

        let mut expected = Vec::new();
        expected.extend_from_slice(binary_header.as_bytes());
        expected.extend_from_slice(&binary_data);
        expected.push(b'\n');

        assert!(
            result.is_some(),
            "Should return Some even with non-UTF8 data containing newline in payload"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Should correctly handle binary data with embedded newline by using length field from header"
        );
    }

    fn string_list_to_bytes(lines: Vec<&str>) -> Bytes {
        let joined = lines.join("\n");
        Bytes::from(joined)
    }

    #[test]
    fn test_modify_envelope_multipler_unique_event_ids() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        let mut body = Vec::new();
        // Envelope header with event_id
        body.extend_from_slice(
            br#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"5cb13bb8-eb7f-4a50-a8d8-9d309fd1049d"}"#,
        );
        body.push(b'\n');
        // Event item
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":27}\n");
        body.extend_from_slice(br#"{"message":"something failed"}"#);
        body.push(b'\n');

        let result = modify_envelope(&Bytes::from(body), &outbound, &[], 3);

        assert!(result.is_some());
        let new_body = result.unwrap();
        let body_str = String::from_utf8(new_body.to_vec()).unwrap();

        // Split by lines and filter for envelope headers (contain event_id but not "type")
        let envelope_headers: Vec<&str> = body_str
            .lines()
            .filter(|line| line.contains("event_id") && !line.contains(r#""type""#))
            .collect();

        assert_eq!(
            envelope_headers.len(),
            3,
            "Should have 3 envelope headers with event_id"
        );

        // Parse each header and extract event_id
        let mut event_ids = Vec::new();
        for header in &envelope_headers {
            let json: Value = serde_json::from_str(header).unwrap();
            let event_id = json.get("event_id").unwrap().as_str().unwrap();
            event_ids.push(event_id.to_string());
        }

        // Verify all event_ids are unique
        assert_eq!(event_ids.len(), 3);
        assert_ne!(event_ids[0], event_ids[1], "Event IDs should be unique");
        assert_ne!(event_ids[1], event_ids[2], "Event IDs should be unique");
        assert_ne!(event_ids[0], event_ids[2], "Event IDs should be unique");

        // Verify none of them are the original event_id
        assert_ne!(
            event_ids[0], "5cb13bb8-eb7f-4a50-a8d8-9d309fd1049d",
            "Should not use original event_id"
        );

        // Verify all envelopes have the updated DSN
        for header in &envelope_headers {
            let json: Value = serde_json::from_str(header).unwrap();
            let dsn = json.get("dsn").unwrap().as_str().unwrap();
            assert_eq!(
                dsn, "https://outbound@o789.ingest.sentry.io/6789",
                "DSN should be updated"
            );
        }
    }

    #[test]
    fn test_modify_envelope_multiplier_with_categories() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let mut body = Vec::new();
        // Envelope header
        body.extend_from_slice(
            br#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"original-id"}"#,
        );
        body.push(b'\n');
        // Attachment item (should be filtered out)
        body.extend_from_slice(b"{\"type\":\"attachment\",\"length\":5}\n");
        body.extend_from_slice(b"hello");
        body.push(b'\n');
        // Event item (should be multiplied)
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");
        body.push(b'\n');

        let categories = vec!["event".to_string()];
        let result = modify_envelope(&Bytes::from(body), &outbound, &categories, 2);

        assert!(result.is_some());
        let new_body = result.unwrap();
        let body_str = String::from_utf8(new_body.to_vec()).unwrap();

        // Count envelope headers (lines containing event_id)
        let envelope_header_count = body_str.lines().filter(|line| line.contains("event_id")).count();
        assert_eq!(
            envelope_header_count, 2,
            "Should have 2 envelope headers when multiplier=2"
        );

        // Count event items (lines containing "type\":\"event")
        let event_item_count = body_str
            .lines()
            .filter(|line| line.contains(r#""type":"event""#))
            .count();
        assert_eq!(
            event_item_count, 2,
            "Should have 2 event items when multiplier=2 with event category"
        );

        // Verify attachment is not included (categories filter)
        assert!(
            !body_str.contains("attachment"),
            "Attachment should be filtered out"
        );
    }

    fn make_test_config() -> ConfigData {
        ConfigData::default()
    }
}
