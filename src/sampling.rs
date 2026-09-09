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

/// Decide whether a payload is kept at `rate`.
///
/// When the trace id is known the decision is a pure function of it, so all
/// envelopes of one trace get the same answer. Streaming SDKs spread a trace
/// over many envelopes, and per-envelope randomness would leave partial
/// traces behind. Without a trace id the decision is random.
///
/// The seed deliberately differs from Relay's, which feeds the trace id into
/// a PCG generator. Sharing its seed would correlate the two decisions and
/// turn the combined rate into `min(mirror, relay)` instead of their product.
pub fn keep(rate: f64, trace_id: Option<&str>) -> bool {
    if rate >= 1.0 {
        return true;
    }
    if rate <= 0.0 {
        return false;
    }

    let draw = match trace_id {
        Some(trace_id) => uniform_from_trace_id(trace_id),
        None => rand::rng().random::<f64>(),
    };

    rate > draw
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const SEED_SALT: &[u8] = b"sentry-mirror:";

/// Map a trace id onto `[0, 1)` with salted FNV-1a and a MurmurHash3
/// finalizer.
///
/// The hash is implemented here so that the mapping stays fixed across Rust
/// and dependency upgrades; every mirror instance must agree on the same
/// traces. FNV alone barely moves the high bits for a change in the last
/// bytes, so the finalizer spreads every input bit over the whole word.
fn uniform_from_trace_id(trace_id: &str) -> f64 {
    let mut hash = FNV_OFFSET;
    for byte in SEED_SALT.iter().chain(trace_id.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^= hash >> 33;

    // The top 53 bits fill a double's mantissa exactly.
    (hash >> 11) as f64 / (1u64 << 53) as f64
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
    fn test_keep_extremes() {
        for i in 0..100 {
            let trace_id = format!("{i:032x}");
            assert!(keep(1.0, None));
            assert!(!keep(0.0, None));
            assert!(keep(1.0, Some(&trace_id)));
            assert!(!keep(0.0, Some(&trace_id)));
        }
    }

    #[test]
    fn test_keep_same_trace_same_decision() {
        let trace_id = "771a43a4192642f0b136d5159a501700";
        let first = keep(0.5, Some(trace_id));
        for _ in 0..100 {
            assert_eq!(keep(0.5, Some(trace_id)), first);
        }
    }

    #[test]
    fn test_keep_is_monotonic_in_rate() {
        for i in 0..1000 {
            let trace_id = format!("{i:032x}");
            if keep(0.1, Some(&trace_id)) {
                assert!(keep(0.5, Some(&trace_id)), "raising the rate keeps a trace");
            }
            if !keep(0.5, Some(&trace_id)) {
                assert!(
                    !keep(0.1, Some(&trace_id)),
                    "lowering the rate drops a trace"
                );
            }
        }
    }

    /// Sequential ids differ only in their last bytes, which is the hardest
    /// input for a byte-wise hash to spread evenly.
    #[test]
    fn test_keep_trace_ids_spread_over_rate() {
        let kept = (0..10_000)
            .map(|i| format!("{i:032x}"))
            .filter(|trace_id| keep(0.25, Some(trace_id)))
            .count();

        assert!((2200..2800).contains(&kept), "kept {kept} of 10000 at 0.25");
    }

    #[test]
    fn test_uniform_from_trace_id_is_stable() {
        // Pin the mapping: a change here changes which traces every mirror keeps.
        assert_eq!(
            uniform_from_trace_id("771a43a4192642f0b136d5159a501700"),
            0.9823153496354838
        );
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
