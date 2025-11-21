use crate::config::ConfigData;
use metrics::Label;
use metrics_exporter_dogstatsd::DogStatsDBuilder;
use std::collections::BTreeMap;

pub struct MetricsConfig {
    /// Metrics collector host/port.
    /// Recording metrics is optional
    pub statsd_addr: Option<String>,

    /// Map of default tags that should be applied to all metrics.
    pub default_tags: BTreeMap<String, String>,
}

impl MetricsConfig {
    pub fn from_config(config: &ConfigData) -> Self {
        MetricsConfig {
            statsd_addr: config.statsd_addr.clone(),
            default_tags: config.default_metrics_tags.clone().unwrap_or_default(),
        }
    }
}

pub fn init(metrics_config: MetricsConfig) {
    if let Some(address) = metrics_config.statsd_addr {
        let labels = metrics_config.default_tags.into_iter()
            .map(|(key, value)| Label::new(key, value))
            .collect();

        let recorder = DogStatsDBuilder::default()
            .with_remote_address(address)
            .expect("Failed to parse metrics address")
            .set_global_prefix("sentrymirror")
            .with_global_labels(labels)
            .build()
            .expect("Could not create DogStatsD exporter");

        metrics::set_global_recorder(recorder).expect("Could not set global metrics recorder")
    }
}
