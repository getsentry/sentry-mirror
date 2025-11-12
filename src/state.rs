use std::collections::HashMap;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::{connect::HttpConnector, Client}, rt::TokioExecutor};

use crate::{config::ConfigData, dsn::{self, DsnKeyRing}};

/// Container for application state.
/// Generally wrapped in an Arc and shared across requests.
pub struct AppState {
    pub config: ConfigData,
    pub keymap: HashMap<String, DsnKeyRing>,
    pub client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl AppState {
    pub fn from_config(config: ConfigData) -> Self {
        // Create a map of inbound -> outbound keys for simpler lookups.
        let keymap = dsn::make_key_map(config.keys.clone());

        // Create a client connection pool that is re-used.
        let https = HttpsConnector::new();
        let client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https);

        Self {
            config,
            keymap,
            client,
        }
    }
}
