//! Platform configuration with strict validation.

use std::collections::BTreeMap;

use observatory_core::{Network, ObservatoryError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ratelimit::RateLimitConfig;

pub use observatory_audit::AuditConfig;

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
    /// A route not listed here falls back to [PlatformConfig::rate_limit].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub route_limits: BTreeMap<String, RateLimitConfig>,
    /// Cross-origin resource sharing policy. Denies all origins by default.
    #[serde(default)]
    pub cors: CorsConfig,
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
            cors: CorsConfig::default(),
        }
    }
}

/// A named configuration profile with per-network overrides.
///
/// Profiles are keyed by a network name (`public`, `testnet`, or `futurenet`)
/// and selected explicitly through `--profile` or the `profile` field. Every
/// override is optional; an omitted field keeps the base configuration value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkProfile {
    /// Overrides `rpc.endpoint` when the profile is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Overrides `analysis.compatibility.policy` when the profile is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

impl NetworkProfile {
    /// Validate the profile's overrides without applying them.
    pub fn validate(&self) -> Result<()> {
        if let Some(endpoint) = &self.endpoint {
            let _ = observatory_rpc::Endpoint::parse(endpoint)?;
        }
        if let Some(policy) = &self.policy {
            match policy.as_str() {
                "strict" | "additive-only" | "additive_only" | "lenient" => {}
                other => {
                    return Err(ObservatoryError::invalid(format!(
                        "unknown compatibility policy `{other}` in profile; \
                         expected strict, additive-only, or lenient"
                    )))
                }
            }
        }
        Ok(())
    }
}

/// Validate that `name` can be used as a profile key.
///
/// Profile keys are network labels, so a typo is rejected instead of silently
/// creating a profile that never matches a network.
pub fn validate_profile_name(name: &str) -> Result<()> {
    name.parse::<Network>().map(|_| ())
}

/// A secure-by-default CORS policy.
///
/// An empty `allowed_origins` list denies every cross-origin request. Credentials
/// are never enabled, so a wildcard origin can never be combined with cookies or
/// authorization state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Exact origins that may make cross-origin requests.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Methods advertised to allowed origins during preflight.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Request headers advertised to allowed origins during preflight.
    #[serde(default)]
    pub allowed_headers: Vec<String>,
}

impl CorsConfig {
    /// Whether `origin` may make cross-origin requests.
    #[must_use]
    pub fn is_allowed_origin(&self, origin: &str) -> bool {
        self.allowed_origins
            .iter()
            .any(|allowed| allowed == "*" || allowed.eq_ignore_ascii_case(origin))
    }

    /// Whether a wildcard origin is configured.
    #[must_use]
    pub fn allows_any_origin(&self) -> bool {
        self.allowed_origins.iter().any(|origin| origin == "*")
    }

    /// Whether credentialed requests are enabled.
    ///
    /// This implementation never advertises `Access-Control-Allow-Credentials`,
    /// which keeps wildcard origins safe.
    #[must_use]
    pub fn credentials_allowed(&self) -> bool {
        false
    }

    /// The methods advertised during preflight.
    #[must_use]
    pub fn methods(&self) -> Vec<String> {
        if self.allowed_methods.is_empty() {
            ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
                .iter()
                .map(|method| (*method).to_string())
                .collect()
        } else {
            self.allowed_methods.clone()
        }
    }

    /// The headers advertised during preflight.
    #[must_use]
    pub fn headers(&self) -> Vec<String> {
        if self.allowed_headers.is_empty() {
            ["content-type", "authorization", "x-api-key"]
                .iter()
                .map(|header| (*header).to_string())
                .collect()
        } else {
            self.allowed_headers.clone()
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

    /// The effective limit for path.
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

    #[test]
    fn cors_denies_by_default() {
        let config = PlatformConfig::default();
        assert!(!config.cors.is_allowed_origin("https://app.example.com"));
        assert!(!config.cors.allows_any_origin());
        assert!(!config.cors.credentials_allowed());
    }

    #[test]
    fn parses_cors_allow_list() {
        let config = PlatformConfig::from_json(&json!({
            "cors": {
                "allowed_origins": ["https://app.example.com"],
                "allowed_methods": ["GET", "POST"],
                "allowed_headers": ["content-type"]
            }
        }))
        .unwrap();
        assert!(config.cors.is_allowed_origin("https://app.example.com"));
        assert!(!config.cors.is_allowed_origin("https://evil.example.com"));
        assert_eq!(config.cors.methods(), vec!["GET", "POST"]);
        assert_eq!(config.cors.headers(), vec!["content-type"]);
    }

    #[test]
    fn selecting_a_profile_applies_its_overrides() {
        let config = crate::ProjectConfig::parse(
            "analysis:\n  compatibility:\n    policy: strict\n\
             rpc:\n  endpoint: https://base.example.org\n\
             profiles:\n  testnet:\n    endpoint: https://testnet.example.org\n    policy: lenient\n",
            crate::ConfigFormat::Yaml,
        )
        .unwrap();

        assert!(
            !config
                .compatibility_policy_for(Some("testnet"))
                .unwrap()
                .function_removal_is_breaking
        );
        assert_eq!(
            config.rpc_endpoint_for(Some("testnet")).unwrap(),
            Some("https://testnet.example.org")
        );

        // Without a selection the base configuration still applies.
        assert!(
            config
                .compatibility_policy_for(None)
                .unwrap()
                .function_removal_is_breaking
        );
        assert_eq!(
            config.rpc_endpoint_for(None).unwrap(),
            Some("https://base.example.org")
        );
    }

    #[test]
    fn configured_default_profile_is_selected() {
        let config = crate::ProjectConfig::parse(
            "profile: public\nprofiles:\n  public:\n    policy: lenient\n",
            crate::ConfigFormat::Yaml,
        )
        .unwrap();
        assert!(
            !config
                .compatibility_policy_for(None)
                .unwrap()
                .function_removal_is_breaking
        );
    }

    #[test]
    fn rejects_malformed_profile_names() {
        let error = crate::ProjectConfig::parse(
            "profiles:\n  devnet:\n    policy: lenient\n",
            crate::ConfigFormat::Yaml,
        )
        .unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));
        assert!(error.to_string().contains("unknown network `devnet`"));
    }

    #[test]
    fn rejects_unknown_selected_profile() {
        let error = crate::ProjectConfig::parse(
            "profile: mainnet\nprofiles:\n  testnet:\n    policy: lenient\n",
            crate::ConfigFormat::Yaml,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown profile `mainnet`"));

        let config = crate::ProjectConfig::parse("{}", crate::ConfigFormat::Yaml).unwrap();
        let error = config.selected_profile(Some("testnet")).unwrap_err();
        assert!(error.to_string().contains("unknown profile `testnet`"));
    }

    #[test]
    fn rejects_invalid_profile_overrides() {
        for yaml in [
            "profiles:\n  testnet:\n    policy: wild\n",
            "profiles:\n  testnet:\n    endpoint: not-a-url\n",
        ] {
            let error = crate::ProjectConfig::parse(yaml, crate::ConfigFormat::Yaml).unwrap_err();
            assert!(matches!(error, ObservatoryError::InvalidInput(_)), "{yaml}");
        }
    }

    #[test]
    fn wildcard_origin_never_enables_credentials() {
        let config = PlatformConfig::from_json(&json!({
            "cors": { "allowed_origins": ["*"] }
        }))
        .unwrap();
        assert!(config.cors.allows_any_origin());
        assert!(!config.cors.credentials_allowed());
    }
}
