use futures::future::join_all;
use hyper_util::client::legacy::{Client, ResponseFuture};
use hyper_util::rt::TokioExecutor;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, warn};

use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes};
use hyper::{Method, StatusCode};
use hyper::{Request, Response};
use hyper_tls::HttpsConnector;

use crate::config::ConfigData;
use crate::dsn;
use crate::request;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type HandlerResult<T> = std::result::Result<T, GenericError>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

pub async fn handle_request<B: Body>(
    req: Request<B>,
    config: Arc<ConfigData>,
    keymap: Arc<HashMap<String, dsn::DsnKeyRing>>,
) -> HandlerResult<Response<BoxBody>>
where
    B::Error: std::error::Error + Sync + Send + 'static,
{
    let method = req.method();
    let path = req.uri().path().to_string();

    metrics::counter!("handle_request.request", "path" => path.clone()).increment(1);

    if method == Method::GET && path == "/health" {
        handle_health(req)
    } else {
        handle_proxy(req, config, keymap).await
    }
}

pub fn handle_health(_req: Request<impl Body>) -> HandlerResult<Response<BoxBody>> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(full("ok"))
        .unwrap())
}

pub async fn handle_proxy<B: Body>(
    req: Request<B>,
    config: Arc<ConfigData>,
    keymap: Arc<HashMap<String, dsn::DsnKeyRing>>,
) -> HandlerResult<Response<BoxBody>>
where
    B::Error: std::error::Error + Sync + Send + 'static,
{
    let method = req.method();
    let uri = req.uri().clone();
    let path = uri.path();
    let headers = req.headers().clone();

    if config.verbose {
        let formatted_headers = headers
            .iter()
            .map(|(key, value)| {
                let value = value.to_str().unwrap_or("<invalid>");
                format!(" {key}: {value}\n")
            })
            .reduce(|mut acc, item| {
                acc.push_str(item.as_ref());
                acc
            });
        debug!("Request: {method} {path}");
        debug!(
            "Headers:\n{}",
            formatted_headers.unwrap_or("Invalid headers".into())
        );
    }

    // All store/envelope requests are POST
    if method != Method::POST {
        metrics::counter!("handle_proxy.incorrect_method", "method" => method.to_string())
            .increment(1);
        debug!("Received a non POST request. method={}", method);

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
        metrics::counter!("handle_proxy.no_dsn").increment(1);

        return Ok(bad_request_response());
    }
    // Match the public key with registered keys
    let public_key = found_dsn.unwrap();
    let keyring = match keymap.get(&public_key) {
        Some(v) => v,
        // If a DSN cannot be found -> empty response
        None => {
            debug!("Could not find a match DSN in the configured keys");
            metrics::counter!("handle_proxy.unknown_dsn").increment(1);

            return Ok(bad_request_response());
        }
    };

    let mut body_bytes = req.collect().await?.to_bytes();
    if config.verbose {
        let body_str = str::from_utf8(&body_bytes).unwrap_or("<binary data>");
        debug!("Request Body: {}", body_str);
    }

    // Bodies can be compressed
    if headers.contains_key("content-encoding") {
        let request_encoding = headers.get("content-encoding").unwrap();
        body_bytes = match request::decode_body(request_encoding, &body_bytes) {
            Ok(decompressed) => decompressed,
            Err(e) => {
                metrics::counter!("handle_proxy.decode_error").increment(1);
                warn!("Could not decode request body: {0:?}", e);

                return Ok(bad_request_response());
            }
        }
    }

    // We'll race requests to the outbound DSN's and once all requests are complete
    // we use the body of the first response
    let mut responses = Vec::new();
    for outbound_dsn in keyring.outbound.iter() {
        metrics::counter!("handle_proxy.outbound_request.start").increment(1);
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
            metrics::counter!("handle_proxy.outbound_request.success").increment(1);

            if config.verbose {
                let response_headers = response.headers();
                if let Some(host) = response_headers.get("Host") {
                    debug!(
                        "Received response from {}",
                        host.to_str().unwrap_or("<invalid host>")
                    );
                }
            }
            if let Ok(response_body) = response.collect().await {
                resp_body = response_body.to_bytes();
                found_body = true;
            }
        } else {
            metrics::counter!("handle_proxy.outbound_request.failed").increment(1);
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

    metrics::counter!("handle_proxy.response").increment(1);
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
    use std::{collections::HashMap, sync::Arc};

    use super::{full, handle_request};
    use crate::{
        config::{ConfigData, KeyRing},
        dsn::{DsnKeyRing, make_key_map},
        logging::LogFormat,
    };
    use http_body_util::{BodyExt, combinators::BoxBody};
    use hyper::{Request, Response, StatusCode, body::Bytes};

    fn make_test_keymap(config: &Arc<ConfigData>) -> Arc<HashMap<String, DsnKeyRing>> {
        let keymap = make_key_map(config.keys.clone());
        Arc::new(keymap)
    }

    fn make_test_config() -> Arc<ConfigData> {
        let config = ConfigData {
            sentry_dsn: None,
            sentry_env: None,
            traces_sample_rate: None,
            log_filter: Some("debug".into()),
            log_format: Some(LogFormat::Text),
            statsd_addr: None,
            default_metrics_tags: None,
            ip: "127.0.0.1".into(),
            port: 3000,
            verbose: true,
            keys: vec![
                KeyRing {
                    inbound: Some(
                        "https://eeeeee12345678901234567890123456@localhost:3000/1234".to_string(),
                    ),
                    outbound: vec![
                        Some(
                            "https://aaaaaaaa123456789012345678901234@target.example.com/5678"
                                .to_string(),
                        ),
                        Some(
                            "https://bbbbbbbb234567890123456789012345@other.example.com/9012"
                                .to_string(),
                        ),
                    ],
                },
                KeyRing {
                    inbound: Some(
                        "https://ddddddd1234567890123456789012345@localhost:3000/3456".to_string(),
                    ),
                    outbound: vec![Some(
                        "https://bbbbbb12345678901234567890123456@target.example.com/7890"
                            .to_string(),
                    )],
                },
            ],
        };

        Arc::new(config)
    }

    async fn extract_body(response: Response<BoxBody<Bytes, hyper::Error>>) -> String {
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();

        String::from_utf8(body_bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_handle_request_health() {
        let config = make_test_config();
        let keymap = make_test_keymap(&config);
        let builder = Request::builder()
            .method("GET")
            .uri("http://example.com/health");
        let request = builder.body(full("")).unwrap();
        let response_res = handle_request(request, config, keymap).await;

        assert!(response_res.is_ok());
        let response = response_res.unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let body = extract_body(response).await;
        assert_eq!("ok", body);
    }

    #[tokio::test]
    async fn test_handle_request_proxy_incorrect_method() {
        let config = make_test_config();
        let keymap = make_test_keymap(&config);
        let builder = Request::builder()
            .method("GET")
            .uri("http://localhost:3000/store");
        let request = builder.body(full("")).unwrap();
        let response_res = handle_request(request, config, keymap).await;

        assert!(response_res.is_ok());
        let response = response_res.unwrap();

        assert_eq!(StatusCode::METHOD_NOT_ALLOWED, response.status());
        let body = extract_body(response).await;
        assert_eq!("Method not allowed", body);
    }

    #[tokio::test]
    async fn test_handle_proxy_no_dsn() {
        let config = make_test_config();
        let keymap = make_test_keymap(&config);
        let builder = Request::builder()
            .method("POST")
            .uri("http://localhost:3000/store");

        let request = builder.body(full("")).unwrap();
        let response_res = handle_request(request, config, keymap).await;

        assert!(response_res.is_ok());
        let response = response_res.unwrap();

        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        let body = extract_body(response).await;
        assert_eq!("No DSN found", body);
    }

    #[tokio::test]
    async fn test_handle_proxy_incorrect_dsn() {
        let config = make_test_config();
        let keymap = make_test_keymap(&config);
        let builder = Request::builder()
            .method("POST")
            .header("Authorization", "sentry_key=not-there")
            .uri("http://localhost:3000/store");

        let request = builder.body(full("")).unwrap();
        let response_res = handle_request(request, config, keymap).await;

        assert!(response_res.is_ok());
        let response = response_res.unwrap();

        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        let body = extract_body(response).await;
        assert_eq!("No DSN found", body);
    }
}
