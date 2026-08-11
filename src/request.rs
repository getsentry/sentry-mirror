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
use crate::envelope::{Envelope, EnvelopeItem};
use crate::sampling::{self, SampleRates};

/// Several headers should not be forwarded as they can cause data truncation, or incorrect behavior.
const NO_COPY_HEADERS: [&str; 3] = ["host", "x-forwarded-for", "content-length"];
const INGEST_PATH_SEGMENTS: [&str; 4] = ["envelope", "minidump", "store", "integration"];

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
        if NO_COPY_HEADERS.contains(&key.as_str()) || key == "content-encoding" {
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

/// Update the envelope body mutating it to incorporate the outbound_dsn and a new event id.
///
/// Will do the following:
///
/// - Replace the DSN key in the envelope header with the outbound DSN.
/// - Will filter envelope items based on the categories.
/// - Can replace event ids in event headers which is necessary when mirror
///   is multiplying requests. Each copy needs a different eventid to preserve
///   the eventid + project uniqueness.
///
/// See the envelope specs https://develop.sentry.dev/sdk/envelopes/
pub fn update_envelope(
    mut envelope: Envelope,
    outbound_dsn: &dsn::Dsn,
    categories: &[String],
    replace_item_id: bool,
    sample_rate: Option<&SampleRates>,
) -> Option<Envelope> {
    // If we need to replace the event_id generate a new v4 uuid
    let new_event_id = if replace_item_id {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };

    // Replace the DSN and event_id if this is a multiplied envelope.
    if envelope.header.get("dsn").is_some() {
        envelope.header["dsn"] = Value::String(outbound_dsn.to_string());
    }
    if let Some(trace) = envelope.header.get("trace")
        && trace.get("public_key").is_some()
    {
        envelope.header["trace"]["public_key"] = Value::String(outbound_dsn.public_key.clone());
    }
    if let Some(event_id) = new_event_id.clone()
        && envelope.header.get("event_id").is_some()
    {
        envelope.header["event_id"] = Value::String(event_id);
    }

    // Apply category filtering.
    envelope
        .items
        .retain(|item| categories.is_empty() || categories.contains(&item_type(item).to_string()));

    // If the envelope has had all items removed we don't send it.
    if envelope.items.is_empty() {
        return None;
    }

    // Sampling is applied after category filtering so that the primary item is
    // chosen from the items that will actually be sent.
    if let Some(rates) = sample_rate
        && rates.is_active()
    {
        let category = primary_category(&envelope.items);
        let rate = rates.rate_for(category);
        if !sampling::roll(rate) {
            metrics::counter!(
                "handle_proxy.outbound_request.sampled_out",
                "outbound_host" => outbound_dsn.host.clone(),
                "category" => category.to_string(),
            )
            .increment(1);
            debug!(
                "Sampling out envelope for {0} with rate {rate}",
                outbound_dsn.host
            );

            return None;
        }
        scale_trace_sample_rate(&mut envelope.header, rate);
    }

    // Replace event ids when the envelope is being multiplied.
    if new_event_id.is_some() {
        envelope.items = envelope
            .items
            .into_iter()
            .map(|mut item| {
                // Replace event_id in the event body to align with the envelope header.
                if let Some(event_id) = new_event_id.clone()
                    && let Ok(mut item_body) = serde_json::from_slice::<Value>(item.body.as_ref())
                    && let Some(old_id) = item_body.get("event_id")
                {
                    item_body["event_id"] = if old_id.to_string().contains("-") {
                        Value::String(event_id.clone())
                    } else {
                        Value::String(event_id.replace("-", "").clone())
                    };
                    item.body = Bytes::from(serde_json::to_vec(&item_body).unwrap());
                }
                item
            })
            .collect();
    }

    Some(envelope)
}

/// The `type` header of an envelope item.
fn item_type(item: &EnvelopeItem) -> &str {
    item.header
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or("")
}

/// The category that a sampling decision is made against.
///
/// Attachments accompany another item, so they are skipped in favour of the
/// item they belong to. Dropping an event but keeping its attachment would
/// leave the attachment orphaned.
fn primary_category(items: &[EnvelopeItem]) -> &str {
    items
        .iter()
        .map(item_type)
        .find(|item_type| *item_type != "attachment")
        .unwrap_or_else(|| items.first().map(item_type).unwrap_or(""))
}

/// Multiply the `trace.sample_rate` envelope header by the rate that mirror
/// sampling used, so that the header reflects the rate data arrived at.
///
/// Sentry serializes this value as a string so that it survives a trip through
/// the `baggage` header, but numbers are handled as well. The value is written
/// back in the shape it was read in.
fn scale_trace_sample_rate(header: &mut Value, factor: f64) {
    // Nothing to do, and rewriting would reformat the value for no reason.
    if factor >= 1.0 {
        return;
    }
    let Some(trace) = header.get_mut("trace") else {
        return;
    };
    let current = match trace.get("sample_rate") {
        Some(Value::String(value)) => value.parse::<f64>().ok().map(|rate| (rate, true)),
        Some(Value::Number(value)) => value.as_f64().map(|rate| (rate, false)),
        Some(other) => {
            warn!("Unexpected trace.sample_rate value {other:?}");
            None
        }
        None => None,
    };
    // Envelopes without a sample rate are left alone. Adding one would claim a
    // client side sample rate that was never used.
    let Some((current, was_string)) = current else {
        return;
    };

    let updated = (current * factor).clamp(0.0, 1.0);
    trace["sample_rate"] = if was_string {
        Value::String(format!("{updated}"))
    } else {
        match serde_json::Number::from_f64(updated) {
            Some(number) => Value::Number(number),
            None => return,
        }
    };
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
    if headers.contains_key("content-encoding") {
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
    use crate::config::SampleRateConfig;
    use crate::envelope;

    fn make_test_config() -> ConfigData {
        ConfigData::default()
    }

    fn string_list_to_bytes(lines: Vec<&str>) -> Bytes {
        let joined = lines.join("\n");
        Bytes::from(joined)
    }

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
    fn make_outbound_request_with_custom_port() {
        let outbound: dsn::Dsn = "http://public@relay:3001/123456".parse().unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/1/envelope/"
            .parse()
            .unwrap();

        let headers = HeaderMap::new();
        let builder = make_outbound_request(&uri, &headers, &outbound);
        let res = builder.body("");
        assert!(res.is_ok());
        let req = res.unwrap();

        let uri = req.uri();
        assert_eq!(uri, "http://relay:3001/api/123456/envelope/");
    }

    #[test]
    fn make_outbound_request_replace_project_id_oltp_url() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/123/integration/oltp/v1/traces/"
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
            "https://o789.ingest.sentry.io/api/6789/integration/oltp/v1/traces/"
        );
    }

    #[test]
    fn make_outbound_request_replace_project_id_minidump_url() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let uri: Uri = "https://o123.ingest.sentry.io/api/123/minidump/"
            .parse()
            .unwrap();

        let headers = HeaderMap::new();
        let builder = make_outbound_request(&uri, &headers, &outbound);
        let res = builder.body("");

        assert!(res.is_ok());
        let req = res.unwrap();
        let uri = req.uri();
        assert_eq!(uri, "https://o789.ingest.sentry.io/api/6789/minidump/");
    }

    #[test]
    fn make_outbound_request_content_encoding_header() {
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

        let builder = make_outbound_request(&uri, &headers, &outbound);
        let res = builder.body("");

        assert!(res.is_ok());
        let req = res.unwrap();
        assert!(
            !req.headers().contains_key("Content-Encoding"),
            "should be absent when envelope_header modification is on"
        );
    }

    #[test]
    fn test_update_envelope_empty_body() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(b"{}\n");
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &[], true, None);

        assert!(result.is_some());
        let envelope = result.unwrap();
        assert_eq!(envelope.items.len(), 1);
        assert_eq!(envelope.items[0].body, vec![]);
    }

    #[test]
    fn test_update_envelope_missing_key() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![r#"{"key":"value"}"#, r#"{"second":"line"}"#, r#"{}"#];
        let body = string_list_to_bytes(lines);
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &[], true, None);

        assert!(result.is_some());
        let updated = result.expect("should be some");
        assert_eq!(updated.items.len(), 1);
        assert_eq!(
            *updated.header.get("key").unwrap(),
            Value::String("value".to_string())
        );
    }

    #[test]
    fn test_update_envelope_replace_dsn_only_first_line() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![
            r#"{"dsn":"value"}"#,
            r#"{"second":"line", "dsn":"value", "length":33}"#,
            r#"{"message":"neat", "dsn":"value"}"#,
        ];
        let body = string_list_to_bytes(lines);
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &[], false, None);

        assert!(result.is_some());
        let updated = result.expect("should be updated");
        // Keys change order in the second line as we parse/serialize item headers
        let expected_lines = vec![
            r#"{"dsn":"https://outbound@o789.ingest.sentry.io/6789"}"#,
            r#"{"dsn":"value","length":33,"second":"line"}"#,
            r#"{"message":"neat", "dsn":"value"}"#,
        ];
        let expected = string_list_to_bytes(expected_lines);
        assert_eq!(updated.to_bytes().trim_ascii(), expected);
    }

    #[test]
    fn test_update_envelope_present() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![
            r#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"5cb13bb8-eb7f-4a50-a8d8-9d309fd1049d"}"#,
            r#"{"type":"event", "length":30}"#,
            r#"{"message":"something failed"}"#,
        ];
        let body = string_list_to_bytes(lines);
        let envelope = envelope::parse(&body).expect("should parse");
        let result = update_envelope(envelope, &outbound, &[], false, None);

        assert!(result.is_some());

        let updated = result.unwrap();
        assert!(!updated.items.is_empty());

        let expected_lines = vec![
            r#"{"dsn":"https://outbound@o789.ingest.sentry.io/6789","event_id":"5cb13bb8-eb7f-4a50-a8d8-9d309fd1049d"}"#,
            r#"{"length":30,"type":"event"}"#,
            r#"{"message":"something failed"}"#,
        ];
        let expected = string_list_to_bytes(expected_lines);
        assert_eq!(updated.to_bytes().trim_ascii(), expected);
    }

    #[test]
    fn test_update_envelope_trace_public_key() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let lines = vec![
            r#"{"dsn":"http://abcdef@localhost:3000/12345","trace":{"public_key":"abcdef"}}"#,
            r#"{"second":"line", "dsn":"value", "length":19}"#,
            r#"{"message":"stuff"}"#,
        ];
        let body = string_list_to_bytes(lines);
        let envelope = envelope::parse(&body).expect("should parse");
        let result = update_envelope(envelope, &outbound, &[], false, None);

        assert!(result.is_some());
        let updated = result.unwrap();
        let expected_lines = vec![
            r#"{"dsn":"https://outbound@o789.ingest.sentry.io/6789","trace":{"public_key":"outbound"}}"#,
            r#"{"dsn":"value","length":19,"second":"line"}"#,
            r#"{"message":"stuff"}"#,
        ];
        let expected = string_list_to_bytes(expected_lines);
        assert_eq!(updated.to_bytes().trim_ascii(), expected);
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

    #[test]
    fn test_update_envelope_body_empty_categories() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(b"{\"dsn\":\"value\"}\n");
        body.extend_from_slice(b"{\"type\":\"attachment\",\"length\":5}\n");
        body.extend_from_slice(b"hello");
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");

        let categories: Vec<String> = vec![];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, false, None);

        assert!(result.is_some(), "Should return Some for valid input");
        let updated = result.unwrap();
        assert_eq!(
            "https://outbound@o789.ingest.sentry.io/6789",
            updated.header.get("dsn").unwrap()
        );

        // No items filtered out.
        assert_eq!(updated.items.len(), 2);
        assert_eq!(updated.items[0].header.get("type").unwrap(), "attachment");
        assert_eq!(updated.items[1].header.get("type").unwrap(), "event");
    }

    #[test]
    fn test_update_envelope_body_with_categories() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(b"{\"dsn\":\"value\"}\n");
        body.extend_from_slice(b"{\"type\":\"attachment\",\"length\":5}\n");
        body.extend_from_slice(b"hello");
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");

        let categories = vec!["event".to_string()];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, false, None);

        assert!(result.is_some());
        let updated = result.unwrap();
        assert_eq!(updated.items.len(), 1, "items should be filtered");
        assert_eq!(updated.items[0].header.get("type").unwrap(), "event");
        assert_eq!(updated.items[0].body, Bytes::from(b"test".to_vec()));
    }

    #[test]
    fn test_update_envelope_body_with_categories_filter_all_items() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(b"{\"type\":\"attachment\",\"length\":5}\n");
        body.extend_from_slice(b"hello");
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");

        let categories = vec!["transaction".to_string()];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, false, None);
        assert!(
            result.is_none(),
            "all items filtered, envelope is not needed"
        );
    }

    #[test]
    fn test_update_envelope_body_replace_id_no_dashes() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":41}\n");
        body.extend_from_slice(b"{\"event_id\":\"oldeventid\",\"other\":\"value\"}");

        let categories = vec![];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, true, None);

        assert!(result.is_some());
        let updated = result.unwrap();
        assert_eq!(updated.items.len(), 1);

        let item = &updated.items[0];
        let body: Value = serde_json::from_slice(&item.body).unwrap();
        let event_id = body.get("event_id").and_then(|v| v.as_str()).unwrap();
        assert!(event_id != "oldeventid");
        assert!(
            !event_id.contains("-"),
            "no dashes in new id as oldeventid had no dashes"
        );
    }

    #[test]
    fn test_update_envelope_body_replace_id_preserve_dashes() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":43}\n");
        body.extend_from_slice(b"{\"event_id\":\"old-event-id\",\"other\":\"value\"}");

        let categories = vec![];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, true, None);

        assert!(result.is_some());
        let updated = result.unwrap();
        assert_eq!(updated.items.len(), 1);

        let item = &updated.items[0];
        let body: Value = serde_json::from_slice(&item.body).unwrap();
        let event_id = body.get("event_id").and_then(|v| v.as_str()).unwrap();
        assert!(event_id != "oldeventid");
        assert!(
            event_id.contains("-"),
            "new event_id should contain dashes when old event_id had dashes"
        );
    }

    #[test]
    fn test_update_envelope_body_multiline_data() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        let attachment_data = "hello\nhello";
        let attachment_header = format!(
            "{{\"type\":\"attachment\",\"length\":{}}}\n",
            attachment_data.len()
        );

        let mut body = Vec::new();
        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(attachment_header.as_bytes());
        body.extend_from_slice(attachment_data.as_bytes());
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");
        body.push(b'\n');

        let categories = vec!["attachment".to_string()];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, false, None);

        assert!(result.is_some());
        let updated = result.unwrap();

        assert_eq!(updated.items.len(), 1);
        assert_eq!(updated.items[0].header.get("type").unwrap(), "attachment");
        assert_eq!(updated.items[0].body, attachment_data.as_bytes());
    }

    #[test]
    fn test_update_envelope_body_item_header_no_length() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        // When items don't have a length, we infer that the next line contains the entire payload.
        // Multi-line payloads *must* have length defined.
        let mut body = Vec::new();
        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(b"{\"type\":\"event\"}\n");
        body.extend_from_slice(b"{\"key\":\"value\", \"event_id\":\"replace\"}");
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"feedback\"}\n");
        body.extend_from_slice(b"{\"event_id\":\"replace\", \"contexts\":{\"feedback\":{}}}");

        let categories: Vec<String> = vec![];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, true, None);

        assert!(result.is_some());
        let updated = result.unwrap();

        assert_eq!(updated.items.len(), 2);

        let item = &updated.items[0];
        let body: Value = serde_json::from_slice(&item.body).unwrap();
        let event_id = body.get("event_id").and_then(|v| v.as_str()).unwrap();
        assert!(event_id != "replace");

        let item = &updated.items[1];
        let body: Value = serde_json::from_slice(&item.body).unwrap();
        let event_id = body.get("event_id").and_then(|v| v.as_str()).unwrap();
        assert!(
            event_id != "replace",
            "event id replacement should work on inferred item lengths"
        );
    }

    #[test]
    fn test_update_envelope_body_binary_data() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        let binary_data: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x0A, 0x80, 0x90, 0xA0, 0xB0, 0xC0];
        let binary_header = format!(
            "{{\"type\":\"attachment\",\"length\":{}}}\n",
            binary_data.len()
        );

        let mut body = Vec::new();
        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(binary_header.as_bytes());
        body.extend_from_slice(&binary_data);
        body.push(b'\n');

        let categories = vec!["attachment".to_string()];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, true, None);

        assert!(result.is_some());
        let updated = result.unwrap();
        assert_eq!(updated.items.len(), 1);
        assert_eq!(updated.items[0].body.to_vec(), binary_data);
    }

    #[test]
    fn test_update_envelope_body_binary_data_replace_id() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();

        let binary_data: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x0A, 0x80, 0x90, 0xA0, 0xB0, 0xC0];
        let binary_header = format!(
            "{{\"type\":\"attachment\",\"length\":{}}}\n",
            binary_data.len()
        );

        let mut body = Vec::new();
        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(binary_header.as_bytes());
        body.extend_from_slice(&binary_data);
        // Trailing newlines are removed
        body.push(b'\n');

        let categories = vec!["attachment".to_string()];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, true, None);

        assert!(result.is_some());
        let updated = result.unwrap();

        assert_eq!(updated.items.len(), 1);
        assert_eq!(updated.items[0].body, &binary_data);
    }

    #[test]
    fn test_update_envelope_replace_item_id_with_categories() {
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
        // Event item (should be included, but no event_id added)
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");
        body.push(b'\n');

        let categories = vec!["event".to_string()];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, true, None);
        assert!(result.is_some());

        let updated = result.unwrap();

        // Attachment should be filtered out.
        assert_eq!(updated.items.len(), 1);
        assert_eq!(updated.items[0].header.get("type").unwrap(), "event");
        assert_eq!(updated.items[0].body, Bytes::from(b"test".to_vec()));

        // event_id in headers is updated
        assert!(updated.header.get("event_id").unwrap() != "original-id");
    }

    #[test]
    fn test_update_envelope_replace_multiple_ids() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let mut body = Vec::new();
        // Envelope header
        body.extend_from_slice(
            br#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"original-id"}"#,
        );
        body.push(b'\n');
        // Feedback item
        body.extend_from_slice(b"{\"type\":\"feedback\",\"length\":40}\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"contexts\":{}}\n");
        // Event item
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":43}\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"message\":\"test\"}\n");

        let categories = vec![];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, true, None);
        assert!(result.is_some());
        let updated = result.unwrap();
        assert_eq!(updated.items.len(), 2);

        let feedback_body: Value = serde_json::from_slice(&updated.items[0].body).unwrap();
        let event_id = feedback_body
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(event_id != "original-id", "event_id should change");

        let event_body: Value = serde_json::from_slice(&updated.items[1].body).unwrap();
        let event_id = event_body.get("event_id").and_then(|v| v.as_str()).unwrap();
        assert!(event_id != "original-id", "event_id should change");
    }

    #[test]
    fn test_modify_envelope_binary_crlf_replace_id() {
        let outbound: dsn::Dsn = "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap();
        let mut body = Vec::new();
        // Envelope header
        body.extend_from_slice(
            br#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"original-id"}"#,
        );
        body.push(b'\n');
        // Attachment item (should be included)
        body.extend_from_slice(b"{\"type\":\"attachment\",\"length\":7}\n");
        body.extend_from_slice(b"hello\r\n");
        body.push(b'\n');
        // Event item (should be included)
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");
        body.push(b'\n');

        let categories = vec![];
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(envelope, &outbound, &categories, true, None);

        assert!(result.is_some());
        let updated = result.unwrap();
        assert_eq!(updated.items.len(), 2);
        assert!(
            *updated.header.get("event_id").unwrap() != Value::String("original-id".to_string()),
            "event id should be changed"
        );
    }

    fn uniform_rates(rate: f64) -> SampleRates {
        let mut problems = Vec::new();
        sampling::normalize(&SampleRateConfig::Uniform(rate), &mut problems)
    }

    fn category_rates(rates: &[(&str, f64)]) -> SampleRates {
        let mut problems = Vec::new();
        let config = SampleRateConfig::PerCategory(
            rates
                .iter()
                .map(|(category, rate)| (category.to_string(), *rate))
                .collect(),
        );

        sampling::normalize(&config, &mut problems)
    }

    /// An envelope with a single item of `item_type`.
    fn sampling_envelope(item_type: &str) -> Envelope {
        let body = string_list_to_bytes(vec![
            r#"{"dsn":"https://deadbeef@ingest.sentry.io/123"}"#,
            &format!(r#"{{"type":"{item_type}","length":4}}"#),
            "test",
        ]);

        envelope::parse(&body).expect("body should parse")
    }

    fn test_dsn() -> dsn::Dsn {
        "https://outbound@o789.ingest.sentry.io/6789"
            .parse()
            .unwrap()
    }

    #[test]
    fn test_update_envelope_sample_rate_zero_drops() {
        let result = update_envelope(
            sampling_envelope("error"),
            &test_dsn(),
            &[],
            false,
            Some(&category_rates(&[("error", 0.0)])),
        );

        assert!(result.is_none(), "a 0.0 rate should drop the envelope");
    }

    #[test]
    fn test_update_envelope_sample_rate_one_keeps() {
        let result = update_envelope(
            sampling_envelope("error"),
            &test_dsn(),
            &[],
            false,
            Some(&category_rates(&[("error", 1.0)])),
        );

        assert!(result.is_some(), "a 1.0 rate should keep the envelope");
    }

    #[test]
    fn test_update_envelope_sample_rate_unlisted_category_kept() {
        let result = update_envelope(
            sampling_envelope("error"),
            &test_dsn(),
            &[],
            false,
            Some(&category_rates(&[("span", 0.0)])),
        );

        assert!(
            result.is_some(),
            "categories without a rate should not be sampled"
        );
    }

    #[test]
    fn test_update_envelope_sample_rate_uniform_zero_drops() {
        let result = update_envelope(
            sampling_envelope("transaction"),
            &test_dsn(),
            &[],
            false,
            Some(&uniform_rates(0.0)),
        );

        assert!(result.is_none(), "uniform rates apply to every category");
    }

    /// The sampling decision is made per envelope using the primary item, so
    /// that an attachment is never separated from the event it belongs to.
    #[test]
    fn test_update_envelope_sample_rate_uses_primary_item() {
        let mut body = Vec::new();
        body.extend_from_slice(b"{\"dsn\":\"value\"}\n");
        body.extend_from_slice(b"{\"type\":\"attachment\",\"length\":5}\n");
        body.extend_from_slice(b"hello");
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");

        // The leading attachment does not drive the decision.
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(
            envelope,
            &test_dsn(),
            &[],
            false,
            Some(&category_rates(&[("attachment", 0.0)])),
        );
        assert!(
            result.is_some(),
            "attachments should not make the decision for the envelope"
        );

        // Dropping the event takes its attachment along with it.
        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(
            envelope,
            &test_dsn(),
            &[],
            false,
            Some(&category_rates(&[("event", 0.0)])),
        );
        assert!(
            result.is_none(),
            "the whole envelope is dropped, including attachments"
        );
    }

    #[test]
    fn test_update_envelope_sample_rate_applied_after_category_filter() {
        let mut body = Vec::new();
        body.extend_from_slice(b"{\"dsn\":\"value\"}\n");
        body.extend_from_slice(b"{\"type\":\"attachment\",\"length\":5}\n");
        body.extend_from_slice(b"hello");
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":4}\n");
        body.extend_from_slice(b"test");

        let envelope = envelope::parse(&body).expect("body should parse");
        let result = update_envelope(
            envelope,
            &test_dsn(),
            &["event".to_string()],
            false,
            Some(&category_rates(&[("attachment", 0.0)])),
        );

        assert!(
            result.is_some(),
            "the attachment is filtered out before sampling decides"
        );
    }

    /// Sentry sends the dynamic sampling context as strings so that it can
    /// survive a trip through the baggage header.
    #[test]
    fn test_scale_trace_sample_rate_string() {
        let mut header =
            serde_json::json!({"trace": {"public_key": "abcdef", "sample_rate": "0.5"}});
        scale_trace_sample_rate(&mut header, 0.5);

        assert_eq!(
            header["trace"]["sample_rate"],
            Value::String("0.25".to_string()),
            "the rate should be multiplied and stay a string"
        );
    }

    #[test]
    fn test_scale_trace_sample_rate_numeric() {
        let mut header = serde_json::json!({"trace": {"public_key": "abcdef", "sample_rate": 0.5}});
        scale_trace_sample_rate(&mut header, 0.5);

        assert_eq!(
            header["trace"]["sample_rate"],
            serde_json::json!(0.25),
            "numeric rates should stay numeric"
        );
    }

    #[test]
    fn test_scale_trace_sample_rate_not_scaled_at_one() {
        let mut header =
            serde_json::json!({"trace": {"public_key": "abcdef", "sample_rate": "0.5"}});
        scale_trace_sample_rate(&mut header, 1.0);

        assert_eq!(
            header["trace"]["sample_rate"],
            Value::String("0.5".to_string()),
            "an unsampled rate should not reformat the value"
        );
    }

    #[test]
    fn test_scale_trace_sample_rate_no_trace_header() {
        let mut header = serde_json::json!({"event_id": "abcdef"});
        scale_trace_sample_rate(&mut header, 0.5);

        assert!(
            header.get("trace").is_none(),
            "a trace header should not be invented"
        );
    }

    #[test]
    fn test_scale_trace_sample_rate_missing_field() {
        let mut header = serde_json::json!({"trace": {"public_key": "abcdef"}});
        scale_trace_sample_rate(&mut header, 0.5);

        assert!(
            header["trace"].get("sample_rate").is_none(),
            "a sample rate should not be added when the client did not send one"
        );
    }

    #[test]
    fn test_scale_trace_sample_rate_unparseable() {
        let mut header =
            serde_json::json!({"trace": {"public_key": "abcdef", "sample_rate": "bogus"}});
        scale_trace_sample_rate(&mut header, 0.5);

        assert_eq!(
            header["trace"]["sample_rate"],
            Value::String("bogus".to_string()),
            "unparseable rates should be left alone"
        );
    }

    /// Every envelope that survives sampling should carry the scaled rate.
    #[test]
    fn test_update_envelope_scales_trace_sample_rate() {
        let body = string_list_to_bytes(vec![
            r#"{"trace":{"public_key":"abcdef","sample_rate":"1.0"}}"#,
            r#"{"type":"transaction","length":4}"#,
            "test",
        ]);
        let rates = uniform_rates(0.5);

        let mut kept = 0;
        for _ in 0..50 {
            let envelope = envelope::parse(&body).expect("body should parse");
            let Some(updated) = update_envelope(envelope, &test_dsn(), &[], false, Some(&rates))
            else {
                continue;
            };
            kept += 1;
            assert_eq!(
                updated.header["trace"]["sample_rate"],
                Value::String("0.5".to_string()),
                "kept envelopes should report the mirrored rate"
            );
        }

        assert!(kept > 0, "a 0.5 rate should keep some envelopes");
    }

    #[test]
    fn test_update_envelope_sample_rate_half_is_probabilistic() {
        let rates = uniform_rates(0.5);
        let mut kept = 0;
        for _ in 0..200 {
            let result = update_envelope(
                sampling_envelope("error"),
                &test_dsn(),
                &[],
                false,
                Some(&rates),
            );
            if result.is_some() {
                kept += 1;
            }
        }

        assert!(kept > 0, "a 0.5 rate should keep some envelopes");
        assert!(kept < 200, "a 0.5 rate should drop some envelopes");
    }
}
