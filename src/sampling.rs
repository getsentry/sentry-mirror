use rand::Rng;
use rand::distr::StandardUniform;
use rand_pcg::Pcg32;
use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;

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
/// The decision is independent of the one Relay makes for the same trace.
/// A Relay rule downstream keeps its own share of the traces the mirror
/// sends, so the combined rate is the product of the two rates, and the
/// server sample rate Relay records stays truthful.
pub fn keep(rate: f64, trace_id: Option<&str>) -> bool {
    if rate >= 1.0 {
        return true;
    }
    if rate <= 0.0 {
        return false;
    }

    let draw = match trace_id.and_then(|id| Uuid::parse_str(id).ok()) {
        Some(trace_id) => uniform_from_trace_id(trace_id),
        None => rand::rng().random::<f64>(),
    };

    draw < rate
}

/// Mixed into the trace id before it seeds the generator.
///
/// Relay seeds the same generator with the bare id. With the same seed the
/// mirror would keep exactly the traces Relay keeps, and a Relay rule below
/// 1.0 would count its rate a second time on data the mirror already sampled.
const MIRROR_SEED_SALT: u128 = 0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834;

/// Map a trace id onto `[0, 1)`.
///
/// The salted id seeds a PCG32 generator, and the first `f64` it produces is
/// the draw. Any change here changes which traces every mirror keeps.
fn uniform_from_trace_id(trace_id: Uuid) -> f64 {
    let seed = trace_id.as_u128() ^ MIRROR_SEED_SALT;
    let mut generator = Pcg32::new((seed >> 64) as u64, seed as u64);
    generator.sample(StandardUniform)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINNED_DRAW: f64 = 0.2580455816534687;
    const RELAY_DRAW: f64 = 0.084458025231689;

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

    /// Pin the mapping. A change here changes which traces every mirror
    /// keeps, and running mirrors would start keeping different traces.
    #[test]
    fn test_uniform_from_trace_id_pinned() {
        let trace_id = Uuid::parse_str("771a43a4192642f0b136d5159a501700").unwrap();
        assert_eq!(uniform_from_trace_id(trace_id), PINNED_DRAW);
    }

    /// The draw Relay makes for a trace, for comparison with the mirror's.
    fn relay_uniform_from_trace_id(trace_id: Uuid) -> f64 {
        let seed = trace_id.as_u128();
        let mut generator = Pcg32::new((seed >> 64) as u64, seed as u64);
        generator.sample(StandardUniform)
    }

    /// A Relay rule downstream must keep its own share of what the mirror
    /// sends, so the mirror's decision must not follow Relay's.
    #[test]
    fn test_keep_is_independent_of_relay() {
        let pinned = Uuid::parse_str("771a43a4192642f0b136d5159a501700").unwrap();
        assert_eq!(
            relay_uniform_from_trace_id(pinned),
            RELAY_DRAW,
            "the reference must match what Relay computes"
        );

        let kept_by_both = (0..10_000)
            .map(|i| Uuid::parse_str(&format!("{i:032x}")).unwrap())
            .filter(|trace_id| relay_uniform_from_trace_id(*trace_id) < 0.5)
            .filter(|trace_id| keep(0.5, Some(&trace_id.simple().to_string())))
            .count();

        assert!(
            (2200..2800).contains(&kept_by_both),
            "both kept {kept_by_both} of 10000, expected about a quarter"
        );
    }

    /// SDKs send trace ids as 32 hex characters; Relay accepts the
    /// hyphenated form as well. Both must map to the same decision.
    #[test]
    fn test_keep_accepts_hyphenated_trace_id() {
        let simple = "771a43a4192642f0b136d5159a501700";
        let hyphenated = "771a43a4-1926-42f0-b136-d5159a501700";
        for rate in [0.1, 0.5, 0.9, 0.99] {
            assert_eq!(keep(rate, Some(simple)), keep(rate, Some(hyphenated)));
        }
    }

    /// A trace id Relay cannot parse gets no trace-level decision there, so
    /// the mirror falls back to a random one instead of a fixed one.
    #[test]
    fn test_keep_invalid_trace_id_is_random() {
        let kept = (0..1000)
            .filter(|_| keep(0.5, Some("not-a-trace-id")))
            .count();

        assert!((400..600).contains(&kept), "kept {kept} of 1000 at 0.5");
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
