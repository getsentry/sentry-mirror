use crate::config::ConfigData;
use metrics_exporter_statsd::StatsdBuilder;
use std::{
    collections::BTreeMap,
    net::{SocketAddr, ToSocketAddrs},
};

pub struct MetricsConfig {
    /// Metrics collector host/port.
    /// Recording metrics is optional
    pub statsd_addr: Option<SocketAddr>,

    /// Map of default tags that should be applied to all metrics.
    pub default_tags: BTreeMap<String, String>,
}

impl MetricsConfig {
    pub fn from_config(config: &ConfigData) -> Self {
        let statsd_addr = if let Some(statsd_addr) = config.statsd_addr.clone() {
            let socket_addrs = statsd_addr
                .to_socket_addrs()
                .expect("Could not resolve into a socket address");
            let [statsd_addr] = socket_addrs.as_slice() else {
                unreachable!("Expect statsd_addr to resolve into a single socket address");
            };
            Some(*statsd_addr)
        } else {
            None
        };

        MetricsConfig {
            statsd_addr: statsd_addr,
            default_tags: config
                .default_metrics_tags
                .clone()
                .or(Some(BTreeMap::new()))
                .unwrap(),
        }
    }
}

pub fn init(metrics_config: MetricsConfig) {
    if let Some(address) = metrics_config.statsd_addr {
        let builder = StatsdBuilder::from(address.ip().to_string(), address.port());

        let recorder = metrics_config
            .default_tags
            .into_iter()
            .fold(
                builder.with_queue_size(5000).with_buffer_size(1024),
                |builder, (key, value)| builder.with_default_tag(key, value),
            )
            .build(Some("sentrymirror"))
            .expect("Could not create StatsdRecorder");

        metrics::set_global_recorder(recorder).expect("Could not set global metrics recorder")
    }
}
