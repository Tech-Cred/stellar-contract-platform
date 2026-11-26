//! Process-local aggregate counters and Prometheus text exposition.
//!
//! The counters are deliberately aggregate and secret-free: they record
//! request volume and outcomes only, never endpoints, keys, or payloads. The
//! exposition is deterministic for a given snapshot so it can be asserted in
//! structural tests. Security events are keyed by a fixed set of reason names.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use observatory_platform::{AuthFailureReason, RateLimitReason, SecurityMetrics};
use serde::Serialize;

/// The Prometheus text exposition content type.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// A point-in-time view of the API counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    /// Every HTTP request handled, including the metrics scrape itself.
    pub requests_total: u64,
    /// Successful contract-analysis requests.
    pub analyses_total: u64,
    /// Responses with a `4xx` or `5xx` status (including rate limiting).
    pub errors_total: u64,
    /// Requests rejected by the rate limiter.
    pub rate_limited_total: u64,
    /// Authentication failures by stable, secret-free reason.
    pub auth_failures: BTreeMap<String, u64>,
    /// Rate-limit rejections by stable, secret-free reason.
    pub rate_limit_rejections: BTreeMap<String, u64>,
}

impl MetricsSnapshot {
    /// Render the snapshot in the Prometheus text exposition format.
    ///
    /// Output is stable: the same snapshot always produces the same bytes.
    /// Reason names are embedded in metric names rather than labels, so the
    /// exposition stays a flat list of counters and cannot leak caller data.
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let mut out = String::new();
        write_counter(
            &mut out,
            "observatory_api_requests_total",
            "Total HTTP requests handled.",
            self.requests_total,
        );
        write_counter(
            &mut out,
            "observatory_api_analyses_total",
            "Successful contract-analysis requests.",
            self.analyses_total,
        );
        write_counter(
            &mut out,
            "observatory_api_errors_total",
            "Responses with a 4xx or 5xx status.",
            self.errors_total,
        );
        write_counter(
            &mut out,
            "observatory_api_rate_limited_total",
            "Requests rejected by the rate limiter.",
            self.rate_limited_total,
        );
        for (reason, value) in &self.auth_failures {
            write_counter(
                &mut out,
                &format!("observatory_api_auth_failures_{reason}_total"),
                "Authentication failures by reason.",
                *value,
            );
        }
        for (reason, value) in &self.rate_limit_rejections {
            write_counter(
                &mut out,
                &format!("observatory_api_rate_limit_rejections_{reason}_total"),
                "Rate-limit rejections by reason.",
                *value,
            );
        }
        out
    }
}

fn write_counter(out: &mut String, name: &str, help: &str, value: u64) {
    writeln!(out, "# HELP {name} {help}").expect("writing to a String cannot fail");
    writeln!(out, "# TYPE {name} counter").expect("writing to a String cannot fail");
    writeln!(out, "{name} {value}").expect("writing to a String cannot fail");
}

/// Monotonic counters shared by all requests to one [`crate::Api`].
#[derive(Debug, Default)]
pub struct Metrics {
    requests: AtomicU64,
    analyses: AtomicU64,
    errors: AtomicU64,
    rate_limited: AtomicU64,
    security: SecurityMetrics,
}

impl Metrics {
    /// Create an empty set of counters.
    #[must_use]
    pub fn new() -> Self {
        Metrics::default()
    }

    /// Record that a request was handled.
    pub fn record_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the outcome of a request. `analysis` marks a successful
    /// contract-analysis call.
    pub fn record_outcome(&self, status: u16, analysis: bool) {
        if analysis {
            self.analyses.fetch_add(1, Ordering::Relaxed);
        }
        if status >= 400 {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        if status == 429 {
            self.rate_limited.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record an authentication failure without retaining any secret.
    pub fn record_auth_failure(&self, reason: AuthFailureReason) {
        self.security.record_auth_failure(reason);
    }

    /// Record a rate-limit rejection without retaining any caller identity.
    pub fn record_rate_limit_rejection(&self, reason: RateLimitReason) {
        self.security.record_rate_limit_rejection(reason);
    }

    /// Take a consistent-enough snapshot of the counters.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        let security = self.security.snapshot();
        MetricsSnapshot {
            requests_total: self.requests.load(Ordering::Relaxed),
            analyses_total: self.analyses.load(Ordering::Relaxed),
            errors_total: self.errors.load(Ordering::Relaxed),
            rate_limited_total: self.rate_limited.load(Ordering::Relaxed),
            auth_failures: security.auth_failures,
            rate_limit_rejections: security.rate_limit_rejections,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_has_help_type_and_values() {
        let snapshot = MetricsSnapshot {
            requests_total: 7,
            analyses_total: 3,
            errors_total: 2,
            rate_limited_total: 1,
            ..MetricsSnapshot::default()
        };
        let text = snapshot.to_prometheus();
        assert!(text.contains("# HELP observatory_api_requests_total"));
        assert!(text.contains("# TYPE observatory_api_requests_total counter"));
        assert!(text.contains("\nobservatory_api_requests_total 7\n"));
        assert!(text.contains("\nobservatory_api_rate_limited_total 1\n"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn exposition_is_deterministic() {
        let snapshot = MetricsSnapshot {
            requests_total: 1,
            analyses_total: 2,
            errors_total: 3,
            rate_limited_total: 4,
            ..MetricsSnapshot::default()
        };
        assert_eq!(snapshot.to_prometheus(), snapshot.to_prometheus());
    }

    #[test]
    fn counters_track_outcomes() {
        let metrics = Metrics::new();
        metrics.record_request();
        metrics.record_outcome(200, true);
        metrics.record_request();
        metrics.record_outcome(429, false);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.requests_total, 2);
        assert_eq!(snapshot.analyses_total, 1);
        assert_eq!(snapshot.errors_total, 1);
        assert_eq!(snapshot.rate_limited_total, 1);
    }

    #[test]
    fn security_counters_are_exposed_by_reason() {
        let metrics = Metrics::new();
        metrics.record_auth_failure(AuthFailureReason::InvalidKey);
        metrics.record_rate_limit_rejection(RateLimitReason::WindowExceeded);
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.auth_failures["invalid_key"], 1);
        assert_eq!(snapshot.rate_limit_rejections["window_exceeded"], 1);
        let text = snapshot.to_prometheus();
        assert!(text.contains("\nobservatory_api_auth_failures_invalid_key_total 1\n"));
        assert!(text.contains("\nobservatory_api_rate_limit_rejections_window_exceeded_total 1\n"));
    }
}
