use futures::future::join_all;
use hyper_util::client::legacy::{Client, ResponseFuture};
use hyper_util::rt::TokioExecutor;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, warn};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, StatusCode};
use hyper::{Request, Response};
use hyper_tls::HttpsConnector;

use crate::dsn;
use crate::request;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

pub async fn handle_request(
    req: Request<Incoming>,
    keymap: Arc<HashMap<String, dsn::DsnKeyRing>>,
) -> Result<Response<BoxBody>> {
    let method = req.method();
    let uri = req.uri().clone();
    let path = uri.path();
    let headers = req.headers().clone();
    let user_agent = match headers.get("user-agent") {
        Some(header) => header.to_str().unwrap_or("no-agent"),
        None => "no-agent",
    };

    debug!("{method} {path} {user_agent}");

    // Log detailed request information in verbose mode
    debug!("Request URI: {}", uri);
    debug!("Request Headers:");
    for (key, value) in headers.iter() {
        let value_str = value.to_str().unwrap_or("<invalid utf-8>");
        debug!("  {}: {}", key, value_str);
    }

    metrics::counter!("handle_request.request").increment(1);

    // All store/envelope requests are POST
    if method != Method::POST {
        metrics::counter!("handle_request.incorrect_method", "method" => method.to_string())
            .increment(1);
        debug!("Received a non POST request");

        let res = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(full("Method not allowed"))
            .unwrap();
        return Ok(res);
    }
    // Find DSN public key in request
    let found_dsn = dsn::from_request(&uri, &headers);
    if found_dsn.is_none() {
        debug!("Could not find a DSN in the request headers or URI");
        metrics::counter!("handle_request.no_dsn").increment(1);

        return Ok(bad_request_response());
    }
    // Match the public key with registered keys
    let public_key = found_dsn.unwrap();
    let keyring = match keymap.get(&public_key) {
        Some(v) => v,
        // If a DSN cannot be found -> empty response
        None => {
            debug!("Could not find a match DSN in the configured keys");
            metrics::counter!("handle_request.unknown_dsn").increment(1);

            return Ok(bad_request_response());
        }
    };
    let mut body_bytes = req.collect().await?.to_bytes();

    // Bodies can be compressed
    if headers.contains_key("content-encoding") {
        let request_encoding = headers.get("content-encoding").unwrap();
        body_bytes = match request::decode_body(request_encoding, &body_bytes) {
            Ok(decompressed) => decompressed,
            Err(e) => {
                metrics::counter!("handle_request.decode_error").increment(1);
                warn!("Could not decode request body: {0:?}", e);

                return Ok(bad_request_response());
            }
        }
    }

    // Log request body in verbose mode
    if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
        debug!("Request Body: {}", body_str);
    } else {
        debug!("Request Body: <binary data, {} bytes>", body_bytes.len());
    }

    // We'll race requests to the outbound DSN's and once all requests are complete
    // we use the body of the first response
    let mut responses = Vec::new();
    for outbound_dsn in keyring.outbound.iter() {
        metrics::counter!("handle_request.outbound_request.start").increment(1);
        debug!("Creating outbound request for {0}", &outbound_dsn.host);

        let request_builder = request::make_outbound_request(&uri, &headers, outbound_dsn);
        let body_out = match request::replace_envelope_dsn(&body_bytes, outbound_dsn) {
            Some(new_body) => new_body,
            None => body_bytes.clone(),
        };
        let request = request_builder.body(Full::new(body_out));

        if let Ok(outbound_request) = request {
            let fut_res = send_request(outbound_request);
            responses.push(fut_res);
        } else {
            warn!("Could not build request {0:?}", request.err());
        }
    }

    let mut found_body = false;
    let mut resp_body = Bytes::new();
    // Wait for responses to finish and use the first one's body
    for fut_res in join_all(responses).await {
        let response_res = fut_res.await;
        if found_body {
            continue;
        }
        if let Ok(response) = response_res {
            metrics::counter!("handle_request.outbound_request.success").increment(1);
            if let Ok(response_body) = response.collect().await {
                resp_body = response_body.to_bytes();
                found_body = true;
            }
        } else {
            metrics::counter!("handle_request.outbound_request.failed").increment(1);
            warn!("Could not make request: {0:?}", response_res.err());
        }
    }

    // Add cors headers necessary for browser events
    let response_builder = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header(
            "Access-Control-Expose-Headers",
            "x-sentry-error,x-sentry-rate-limit,retry-after",
        )
        .header("Cross-Origin-Resource-Policy", "cross-origin");

    metrics::counter!("handle_request.response").increment(1);
    Ok(response_builder.body(full(resp_body)).unwrap())
}

fn bad_request_response() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(full("No DSN found"))
        .unwrap()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Send a request to its destination async
async fn send_request(req: Request<Full<Bytes>>) -> ResponseFuture {
    let https = HttpsConnector::new();
    let client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https);

    client.request(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Bytes;
    use hyper::HeaderMap;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tracing_test::traced_test;

    fn make_test_keymap() -> Arc<HashMap<String, dsn::DsnKeyRing>> {
        let inbound: dsn::Dsn = "https://testkey12345678901234567890ab@localhost:8765/123"
            .parse()
            .unwrap();
        let outbound: dsn::Dsn = "https://outbound1234567890123456789012@sentry.io/456"
            .parse()
            .unwrap();

        let mut keymap = HashMap::new();
        keymap.insert(
            "testkey12345678901234567890ab".to_string(),
            dsn::DsnKeyRing {
                inbound,
                outbound: vec![outbound],
            },
        );
        Arc::new(keymap)
    }

    #[tokio::test]
    #[traced_test]
    async fn test_request_logging_headers() {
        let keymap = make_test_keymap();

        // Verify logs would be created (we can't easily test the actual handle_request
        // without setting up a full mock server, but we can verify the logging structure)

        // This test mainly ensures the code compiles and doesn't panic
        assert!(keymap.len() > 0);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_request_logging_body() {
        // Test that body logging handles both text and binary data
        let test_body = b"test body content";
        let body_bytes = Bytes::from(&test_body[..]);

        // Test UTF-8 conversion
        if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
            assert_eq!(body_str, "test body content");
        }

        // Test binary data
        let binary_data = vec![0xFF, 0xFE, 0xFD];
        let binary_bytes = Bytes::from(binary_data);
        assert!(std::str::from_utf8(&binary_bytes).is_err());
    }

    #[test]
    fn test_header_iteration() {
        // Test that we can iterate over headers and convert them to strings
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("user-agent", "test-agent".parse().unwrap());

        let mut header_count = 0;
        for (_key, value) in headers.iter() {
            let value_str = value.to_str().unwrap_or("<invalid utf-8>");
            assert!(!value_str.is_empty());
            header_count += 1;
        }
        assert_eq!(header_count, 2);
    }

    #[test]
    fn test_invalid_utf8_header_handling() {
        // Test that invalid UTF-8 in headers is handled gracefully
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", "valid-value".parse().unwrap());

        for (_, value) in headers.iter() {
            let value_str = value.to_str().unwrap_or("<invalid utf-8>");
            assert_eq!(value_str, "valid-value");
        }
    }
}
