//! Bounded, secret-free counters for security-relevant events.
//!
//! Operators need to see authentication failures and rate-limit rejections,
//! but the counters must never become a side channel for credentials or
//! callers. Reasons are therefore a fixed set of stable names: an arbitrary
//! string (which might contain a key, header, or path) can never be inserted
//! into the counter map. This also bounds memory use regardless of traffic.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Stable reasons for an authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureReason {
    /// No credential was supplied for a route that requires one.
    MissingKey,
    /// A credential was supplied but did not authenticate.
    InvalidKey,
    /// The authenticated principal lacked the required permission.
    InsufficientPermission,
}

impl AuthFailureReason {
    /// The stable, secret-free name used as a counter key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthFailureReason::MissingKey => "missing_key",
            AuthFailureReason::InvalidKey => "invalid_key",
            AuthFailureReason::InsufficientPermission => "insufficient_permission",
        }
    }

    const fn index(self) -> usize {
        match self {
            AuthFailureReason::MissingKey => 0,
            AuthFailureReason::InvalidKey => 1,
            AuthFailureReason::InsufficientPermission => 2,
        }
    }
}

/// Every authentication failure reason, in a stable order.
pub const AUTH_FAILURE_REASONS: [AuthFailureReason; 3] = [
    AuthFailureReason::MissingKey,
    AuthFailureReason::InvalidKey,
    AuthFailureReason::InsufficientPermission,
];

/// Stable reasons for a rate-limit rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitReason {
    /// The caller exhausted the fixed-window budget for the route.
    WindowExceeded,
}

impl RateLimitReason {
    /// The stable, secret-free name used as a counter key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RateLimitReason::WindowExceeded => "window_exceeded",
        }
    }

    const fn index(self) -> usize {
        match self {
            RateLimitReason::WindowExceeded => 0,
        }
    }
}

/// Every rate-limit rejection reason, in a stable order.
pub const RATE_LIMIT_REASONS: [RateLimitReason; 1] = [RateLimitReason::WindowExceeded];

/// A point-in-time view of the security counters.
///
/// Both maps include every known reason so a scrape is stable from the first
/// request onward. The keys are enum names, never caller-supplied data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityMetricsSnapshot {
    /// Authentication failures by reason.
    pub auth_failures: BTreeMap<String, u64>,
    /// Rate-limit rejections by reason.
    pub rate_limit_rejections: BTreeMap<String, u64>,
}

/// Monotonic, bounded counters shared by all requests to one application.
#[derive(Debug)]
pub struct SecurityMetrics {
    auth_failures: [AtomicU64; AUTH_FAILURE_REASONS.len()],
    rate_limit_rejections: [AtomicU64; RATE_LIMIT_REASONS.len()],
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self {
            auth_failures: std::array::from_fn(|_| AtomicU64::new(0)),
            rate_limit_rejections: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl SecurityMetrics {
    /// Create an empty set of security counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an authentication failure. The reason never contains a secret.
    pub fn record_auth_failure(&self, reason: AuthFailureReason) {
        self.auth_failures[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rate-limit rejection. The reason never contains a secret.
    pub fn record_rate_limit_rejection(&self, reason: RateLimitReason) {
        self.rate_limit_rejections[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Take a consistent-enough snapshot of the counters.
    #[must_use]
    pub fn snapshot(&self) -> SecurityMetricsSnapshot {
        SecurityMetricsSnapshot {
            auth_failures: AUTH_FAILURE_REASONS
                .iter()
                .map(|reason| {
                    (
                        reason.as_str().to_string(),
                        self.auth_failures[reason.index()].load(Ordering::Relaxed),
                    )
                })
                .collect(),
            rate_limit_rejections: RATE_LIMIT_REASONS
                .iter()
                .map(|reason| {
                    (
                        reason.as_str().to_string(),
                        self.rate_limit_rejections[reason.index()].load(Ordering::Relaxed),
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_failures_increment_by_reason() {
        let metrics = SecurityMetrics::new();
        metrics.record_auth_failure(AuthFailureReason::InvalidKey);
        metrics.record_auth_failure(AuthFailureReason::InvalidKey);
        metrics.record_auth_failure(AuthFailureReason::MissingKey);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.auth_failures["invalid_key"], 2);
        assert_eq!(snapshot.auth_failures["missing_key"], 1);
        assert_eq!(snapshot.auth_failures["insufficient_permission"], 0);
        assert_eq!(snapshot.auth_failures.len(), AUTH_FAILURE_REASONS.len());
    }

    #[test]
    fn rate_limit_rejections_increment_by_reason() {
        let metrics = SecurityMetrics::new();
        metrics.record_rate_limit_rejection(RateLimitReason::WindowExceeded);
        metrics.record_rate_limit_rejection(RateLimitReason::WindowExceeded);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.rate_limit_rejections["window_exceeded"], 2);
        assert_eq!(
            snapshot.rate_limit_rejections.len(),
            RATE_LIMIT_REASONS.len()
        );
    }

    #[test]
    fn snapshots_contain_only_fixed_reason_names() {
        let metrics = SecurityMetrics::new();
        metrics.record_auth_failure(AuthFailureReason::InvalidKey);
        metrics.record_rate_limit_rejection(RateLimitReason::WindowExceeded);
        let snapshot = metrics.snapshot();

        assert!(snapshot.auth_failures.keys().all(|key| AUTH_FAILURE_REASONS
            .iter()
            .any(|reason| reason.as_str() == key)));
        assert!(snapshot
            .rate_limit_rejections
            .keys()
            .all(|key| RATE_LIMIT_REASONS
                .iter()
                .any(|reason| reason.as_str() == key)));
    }
}
