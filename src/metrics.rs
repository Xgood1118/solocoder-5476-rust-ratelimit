use prometheus::{
    IntCounter, IntCounterVec, IntGauge, IntGaugeVec, HistogramOpts, HistogramVec,
    Registry, Encoder, TextEncoder,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub requests_total: IntCounterVec,
    pub requests_blocked: IntCounterVec,
    pub current_remaining: IntGaugeVec,
    pub request_duration: HistogramVec,
    pub rule_hits: IntCounterVec,
    pub rule_misses: IntCounterVec,
    pub rule_blocked: IntCounterVec,
    pub active_rules: IntGauge,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ratelimit_requests_total",
                "Total number of rate limit check requests",
            ),
            &["rule_id", "result"],
        )
        .unwrap();

        let requests_blocked = IntCounterVec::new(
            prometheus::Opts::new(
                "ratelimit_requests_blocked_total",
                "Total number of blocked requests",
            ),
            &["rule_id"],
        )
        .unwrap();

        let current_remaining = IntGaugeVec::new(
            prometheus::Opts::new(
                "ratelimit_current_remaining",
                "Current remaining tokens/count for a rule key",
            ),
            &["rule_id"],
        )
        .unwrap();

        let histogram_opts = HistogramOpts::new(
            "ratelimit_request_duration_seconds",
            "Duration of rate limit check requests",
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]);

        let request_duration = HistogramVec::new(histogram_opts, &["rule_id"]).unwrap();

        let rule_hits = IntCounterVec::new(
            prometheus::Opts::new(
                "ratelimit_rule_hits_total",
                "Total number of times a rule was matched",
            ),
            &["rule_id"],
        )
        .unwrap();

        let rule_misses = IntCounterVec::new(
            prometheus::Opts::new(
                "ratelimit_rule_misses_total",
                "Total number of times a rule was not matched",
            ),
            &["rule_id"],
        )
        .unwrap();

        let rule_blocked = IntCounterVec::new(
            prometheus::Opts::new(
                "ratelimit_rule_blocked_total",
                "Total number of times a rule blocked a request",
            ),
            &["rule_id"],
        )
        .unwrap();

        let active_rules = IntGauge::new(
            "ratelimit_active_rules",
            "Number of active rate limit rules",
        )
        .unwrap();

        registry.register(Box::new(requests_total.clone())).unwrap();
        registry.register(Box::new(requests_blocked.clone())).unwrap();
        registry.register(Box::new(current_remaining.clone())).unwrap();
        registry.register(Box::new(request_duration.clone())).unwrap();
        registry.register(Box::new(rule_hits.clone())).unwrap();
        registry.register(Box::new(rule_misses.clone())).unwrap();
        registry.register(Box::new(rule_blocked.clone())).unwrap();
        registry.register(Box::new(active_rules.clone())).unwrap();

        Self {
            registry,
            requests_total,
            requests_blocked,
            current_remaining,
            request_duration,
            rule_hits,
            rule_misses,
            rule_blocked,
            active_rules,
        }
    }

    pub fn record_check(&self, rule_id: &str, allowed: bool, remaining: u64, duration_ms: f64) {
        let result = if allowed { "allowed" } else { "blocked" };
        self.requests_total
            .with_label_values(&[rule_id, result])
            .inc();

        if !allowed {
            self.requests_blocked
                .with_label_values(&[rule_id])
                .inc();
            self.rule_blocked
                .with_label_values(&[rule_id])
                .inc();
        }

        self.current_remaining
            .with_label_values(&[rule_id])
            .set(remaining as i64);

        self.request_duration
            .with_label_values(&[rule_id])
            .observe(duration_ms / 1000.0);

        self.rule_hits.with_label_values(&[rule_id]).inc();
    }

    pub fn set_active_rules(&self, count: usize) {
        self.active_rules.set(count as i64);
    }

    pub fn gather_text(&self) -> Vec<u8> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap_or(());
        buffer
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
