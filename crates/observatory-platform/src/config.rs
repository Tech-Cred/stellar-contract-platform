//! Platform configuration with strict validation.

use std::collections::BTreeMap;

use observatory_core::{ObservatoryError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ratelimit::RateLimitConfig;

/// Configuration for the platform/API layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformConfig {
    /// Whether analysis endpoints require authentication.
    #[serde(default = "default_true")]
    pub require_auth: bool,
    /// Default rate limit applied to any route without an override.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Optional per-route limits, keyed by exact request path.
    ///
    /// A route not listed here falls back to [`PlatformConfig::rate_limit`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub route_limits: BTreeMap<String, RateLimitConfig>,
}

fn default_true() -> bool {
    true
}

impl Default for PlatformConfig {
    fn default() -> Self {
        PlatformConfig {
            require_auth: true,
            rate_limit: RateLimitConfig::default(),
            route_limits: BTreeMap::new(),
        }
    }
}

impl PlatformConfig {
    /// Parse configuration from a JSON value, rejecting unknown fields.
    pub fn from_json(value: &Value) -> Result<Self> {
        serde_json::from_value(value.clone()).map_err(|error| {
            ObservatoryError::invalid(format!("invalid platform configuration: {error}"))
        })
    }

    /// The effective limit for `path`.
    ///
    /// Exact-path overrides win; otherwise the global default applies.
    #[must_use]
    pub fn rate_limit_for(&self, path: &str) -> RateLimitConfig {
        self.route_limits
            .get(path)
            .copied()
            .unwrap_or(self.rate_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_are_sane() {
        let config = PlatformConfig::default();
        assert!(config.require_auth);
        assert_eq!(config.rate_limit.limit, 120);
        assert!(config.route_limits.is_empty());
        assert_eq!(config.rate_limit_for("/api/v1/health").limit, 120);
    }

    #[test]
    fn route_limits_override_the_default() {
        let config = PlatformConfig::from_json(&json!({
            "rate_limit": { "limit": 60, "window_secs": 60 },
            "route_limits": {
                "/api/v1/contracts/inspect": { "limit": 5, "window_secs": 60 }
            }
        }))
        .unwrap();
        assert_eq!(config.rate_limit_for("/api/v1/health").limit, 60);
        let inspect = config.rate_limit_for("/api/v1/contracts/inspect");
        assert_eq!(inspect.limit, 5);
        assert_eq!(inspect.window_secs, 60);
    }

    #[test]
    fn parses_valid_configuration() {
        let config = PlatformConfig::from_json(&json!({
            "require_auth": false,
            "rate_limit": { "limit": 10, "window_secs": 30 }
        }))
        .unwrap();
        assert!(!config.require_auth);
        assert_eq!(config.rate_limit.limit, 10);
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = PlatformConfig::from_json(&json!({ "unknown": true })).unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));
    }
}
