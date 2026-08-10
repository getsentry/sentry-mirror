use rand::Rng;
use std::collections::BTreeMap;
use std::fmt;

use crate::config::SampleRateConfig;

/// Normalized and validated sampling rates for a single outbound DSN.
///
/// Both configuration shapes collapse into this one. A uniform rate becomes
/// `default_rate` with an empty map, while a per-category map leaves
/// `default_rate` at 1.0 so that categories which are not listed are not
/// sampled.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleRates {
    /// The rate used for categories missing from `per_category`.
    default_rate: f64,

    /// Rates for individual envelope item categories.
    per_category: BTreeMap<String, f64>,
}

impl SampleRates {
    /// The sample rate for a category. Categories that have no explicit
    /// rate use the default rate.
    pub fn rate_for(&self, category: &str) -> f64 {
        *self
            .per_category
            .get(category)
            .unwrap_or(&self.default_rate)
    }

    /// Whether any configured rate can drop data. Lets request handling skip
    /// sampling work entirely when rates are all 1.0.
    pub fn is_active(&self) -> bool {
        self.default_rate < 1.0 || self.per_category.values().any(|rate| *rate < 1.0)
    }
}

impl fmt::Display for SampleRates {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.per_category.is_empty() {
            return write!(f, "{}", self.default_rate);
        }
        let pairs = self
            .per_category
            .iter()
            .map(|(category, rate)| format!("{category}: {rate}"))
            .collect::<Vec<String>>();

        write!(
            f,
            "{{{}}} (default {})",
            pairs.join(", "),
            self.default_rate
        )
    }
}

/// Convert configuration into validated rates.
///
/// Rates outside of 0.0 - 1.0 are clamped to the nearest boundary and values
/// that are not numbers are ignored. Each correction is appended to `problems`
/// so that callers can log them with the DSN they belong to.
pub fn normalize(config: &SampleRateConfig, problems: &mut Vec<String>) -> SampleRates {
    match config {
        SampleRateConfig::Uniform(rate) => SampleRates {
            default_rate: clamp_rate(None, *rate, problems),
            per_category: BTreeMap::new(),
        },
        SampleRateConfig::PerCategory(rates) => SampleRates {
            default_rate: 1.0,
            per_category: rates
                .iter()
                .map(|(category, rate)| {
                    (
                        category.clone(),
                        clamp_rate(Some(category), *rate, problems),
                    )
                })
                .collect(),
        },
    }
}

/// Clamp a rate into 0.0 - 1.0, recording a message when the value is changed.
fn clamp_rate(category: Option<&str>, rate: f64, problems: &mut Vec<String>) -> f64 {
    let target = match category {
        Some(name) => format!("category {name}"),
        None => "all categories".to_string(),
    };
    // clamp() returns NaN for NaN, which would silently drop all traffic.
    if !rate.is_finite() {
        problems.push(format!(
            "sample_rate {rate} for {target} is not a number, using 1.0"
        ));
        return 1.0;
    }
    if !(0.0..=1.0).contains(&rate) {
        let clamped = rate.clamp(0.0, 1.0);
        problems.push(format!(
            "sample_rate {rate} for {target} is outside of 0.0 - 1.0, clamped to {clamped}"
        ));
        return clamped;
    }

    rate
}

/// Draw against the thread local rng to decide if an item is kept.
pub fn roll(rate: f64) -> bool {
    if rate >= 1.0 {
        return true;
    }
    if rate <= 0.0 {
        return false;
    }

    rate < rand::rng().random::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn per_category(rates: &[(&str, f64)]) -> SampleRateConfig {
        SampleRateConfig::PerCategory(
            rates
                .iter()
                .map(|(category, rate)| (category.to_string(), *rate))
                .collect(),
        )
    }

    fn normalized(config: &SampleRateConfig) -> SampleRates {
        let mut problems = Vec::new();
        normalize(config, &mut problems)
    }

    #[test]
    fn test_rate_for_uniform() {
        let rates = normalized(&SampleRateConfig::Uniform(0.25));

        assert_eq!(rates.rate_for("error"), 0.25);
        assert_eq!(rates.rate_for("transaction"), 0.25);
        assert_eq!(rates.rate_for(""), 0.25);
    }

    #[test]
    fn test_rate_for_map_defaults_to_one() {
        let rates = normalized(&per_category(&[("span", 0.05)]));

        assert_eq!(rates.rate_for("span"), 0.05);
        assert_eq!(
            rates.rate_for("error"),
            1.0,
            "categories without a rate are not sampled"
        );
        assert_eq!(
            rates.rate_for(""),
            1.0,
            "payloads without a category are not sampled"
        );
    }

    #[test]
    fn test_normalize_clamps_above_one() {
        let mut problems = Vec::new();
        let rates = normalize(&per_category(&[("error", 1.5)]), &mut problems);

        assert_eq!(rates.rate_for("error"), 1.0);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("category error"), "{}", problems[0]);
    }

    #[test]
    fn test_normalize_clamps_below_zero() {
        let mut problems = Vec::new();
        let rates = normalize(&SampleRateConfig::Uniform(-0.5), &mut problems);

        assert_eq!(rates.rate_for("error"), 0.0);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("clamped to 0"), "{}", problems[0]);
    }

    #[test]
    fn test_normalize_non_finite() {
        let mut problems = Vec::new();
        let rates = normalize(
            &per_category(&[("error", f64::NAN), ("span", f64::INFINITY)]),
            &mut problems,
        );

        assert_eq!(
            rates.rate_for("error"),
            1.0,
            "NaN should not drop all traffic"
        );
        assert_eq!(rates.rate_for("span"), 1.0);
        assert_eq!(problems.len(), 2);
    }

    #[test]
    fn test_normalize_in_range_no_problems() {
        let mut problems = Vec::new();
        normalize(
            &per_category(&[("error", 0.0), ("span", 0.5), ("log", 1.0)]),
            &mut problems,
        );

        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn test_is_active() {
        assert!(!normalized(&SampleRateConfig::Uniform(1.0)).is_active());
        assert!(!normalized(&per_category(&[("error", 1.0)])).is_active());
        assert!(normalized(&SampleRateConfig::Uniform(0.5)).is_active());
        assert!(normalized(&per_category(&[("error", 0.0)])).is_active());
    }

    #[test]
    fn test_roll_deterministic_extremes() {
        for _ in 0..100 {
            assert!(roll(1.0));
            assert!(!roll(0.0));
        }
    }

    #[test]
    fn test_display_uniform() {
        assert_eq!(
            normalized(&SampleRateConfig::Uniform(0.5)).to_string(),
            "0.5"
        );
    }

    #[test]
    fn test_display_per_category() {
        let rates = normalized(&per_category(&[("span", 0.05), ("error", 0.5)]));

        assert_eq!(rates.to_string(), "{error: 0.5, span: 0.05} (default 1)");
    }
}
