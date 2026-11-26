//! Project configuration (`observatory.yml`, `.yaml`, `.toml`, or `.json`).
//!
//! The configuration is validated strictly: unknown fields are rejected so a
//! typo cannot silently disable a setting. The schema is intentionally small and
//! only exposes settings that the implementation actually honours.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use observatory_core::{Network, ObservatoryError, Result};
use serde::{Deserialize, Serialize};

use crate::config::{validate_profile_name, AuditConfig, NetworkProfile};
use crate::ratelimit::RateLimitConfig;
use crate::rbac::Role;

/// The filename stems discovered automatically, in priority order.
pub const DISCOVERY_NAMES: &[&str] = &[
    "observatory.yml",
    "observatory.yaml",
    "observatory.toml",
    "observatory.json",
];

/// A complete project configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    /// Project identity.
    #[serde(default)]
    pub project: ProjectSection,
    /// Analysis defaults.
    #[serde(default)]
    pub analysis: AnalysisSection,
    /// RPC defaults.
    #[serde(default)]
    pub rpc: RpcSection,
    /// API/platform defaults.
    #[serde(default)]
    pub api: ApiSection,
    /// CI defaults.
    #[serde(default)]
    pub ci: CiSection,
    /// Audit rule selection and severity overrides.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Named per-network override profiles, keyed by network name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, NetworkProfile>,
    /// Profile selected when `--profile` is omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// Project identity.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSection {
    /// Project name.
    #[serde(default)]
    pub name: Option<String>,
    /// Default network label.
    #[serde(default)]
    pub network: Option<String>,
}

/// Analysis defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSection {
    /// Compatibility analysis defaults.
    #[serde(default)]
    pub compatibility: CompatibilitySection,
}

/// Compatibility defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilitySection {
    /// Policy name: `strict`, `additive-only`, or `lenient`.
    #[serde(default = "default_policy")]
    pub policy: String,
}

fn default_policy() -> String {
    "strict".to_string()
}

impl Default for CompatibilitySection {
    fn default() -> Self {
        CompatibilitySection {
            policy: default_policy(),
        }
    }
}

fn parse_compatibility_policy(name: &str) -> Result<crate::CompatibilityPolicy> {
    match name {
        "strict" => Ok(crate::CompatibilityPolicy::strict()),
        "additive-only" | "additive_only" => Ok(crate::CompatibilityPolicy::additive_only()),
        "lenient" => Ok(crate::CompatibilityPolicy::lenient()),
        other => Err(ObservatoryError::invalid(format!(
            "unknown compatibility policy `{other}`; expected strict, additive-only, or lenient"
        ))),
    }
}

/// RPC defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcSection {
    /// Default endpoint URL.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Connect timeout in seconds; defaults to 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,
    /// Read timeout in seconds; defaults to 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_timeout_secs: Option<u64>,
    /// Maximum RPC response body size in bytes; defaults to 8 MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<usize>,
}

/// API/platform defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSection {
    /// Whether analysis endpoints require authentication.
    #[serde(default = "default_true")]
    pub require_auth: bool,
    /// Optional rate-limit override.
    #[serde(default)]
    pub rate_limit: Option<RateLimitSection>,
    /// Optional per-route limits, keyed by exact request path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub route_limits: BTreeMap<String, RateLimitSection>,
    /// Optional CORS policy; an empty allow-list denies every cross-origin call.
    #[serde(default)]
    pub cors: CorsSection,
}

fn default_true() -> bool {
    true
}

impl Default for ApiSection {
    fn default() -> Self {
        ApiSection {
            require_auth: true,
            rate_limit: None,
            route_limits: BTreeMap::new(),
            cors: CorsSection::default(),
        }
    }
}

/// CORS configuration for the project file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CorsSection {
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

/// Rate-limit configuration for the project file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSection {
    /// Requests per window.
    pub limit: u32,
    /// Window length in seconds.
    pub window_secs: u64,
}

/// CI defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiSection {
    /// Comma-separated verification statuses that should fail the build.
    #[serde(default)]
    pub fail_on: Option<String>,
}

impl CiSection {
    /// Resolve the statuses that fail a build.
    ///
    /// Defaults to every failing status; `MATCH` is rejected because a match
    /// never fails a build.
    pub fn failure_statuses(&self) -> Result<BTreeSet<String>> {
        let Some(fail_on) = &self.fail_on else {
            return Ok(["MISMATCH", "INSUFFICIENT_DATA", "ERROR"]
                .into_iter()
                .map(str::to_string)
                .collect());
        };
        let mut statuses = BTreeSet::new();
        for status in fail_on.split(',') {
            let status = status.trim().to_ascii_uppercase();
            match status.as_str() {
                "MISMATCH" | "INSUFFICIENT_DATA" | "ERROR" => {
                    statuses.insert(status);
                }
                "MATCH" => {
                    return Err(ObservatoryError::invalid(
                        "ci.fail_on cannot include MATCH; a match never fails the build",
                    ))
                }
                other => {
                    return Err(ObservatoryError::invalid(format!(
                        "unknown verification status `{other}` in ci.fail_on; \
                         expected MISMATCH, INSUFFICIENT_DATA, or ERROR"
                    )))
                }
            }
        }
        Ok(statuses)
    }
}

/// A supported configuration file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    /// YAML.
    Yaml,
    /// TOML.
    Toml,
    /// JSON.
    Json,
}

impl ConfigFormat {
    /// Infer the format from a file extension.
    pub fn from_path(path: &Path) -> Result<Self> {
        match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("yml") | Some("yaml") => Ok(ConfigFormat::Yaml),
            Some("toml") => Ok(ConfigFormat::Toml),
            Some("json") => Ok(ConfigFormat::Json),
            other => Err(ObservatoryError::unsupported(format!(
                "unsupported configuration extension `{}`; expected yml, yaml, toml, or json",
                other.unwrap_or("<none>")
            ))),
        }
    }
}

impl ProjectConfig {
    /// Parse configuration text in the given format.
    pub fn parse(input: &str, format: ConfigFormat) -> Result<Self> {
        let parsed = match format {
            ConfigFormat::Yaml => serde_yaml_ng::from_str(input).map_err(|error| error.to_string()),
            ConfigFormat::Toml => toml::from_str(input).map_err(|error| error.to_string()),
            ConfigFormat::Json => serde_json::from_str(input).map_err(|error| error.to_string()),
        };
        let config: Self = parsed.map_err(|error| {
            ObservatoryError::invalid(format!("invalid configuration: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from a path, inferring the format.
    pub fn from_path(path: &Path) -> Result<Self> {
        let format = ConfigFormat::from_path(path)?;
        let text = std::fs::read_to_string(path).map_err(|error| {
            ObservatoryError::invalid(format!("cannot read `{}`: {error}", path.display()))
        })?;
        Self::parse(&text, format)
    }

    /// Find and load a configuration file in `directory`, if one exists.
    pub fn discover(directory: &Path) -> Result<Option<(PathBuf, Self)>> {
        for name in DISCOVERY_NAMES {
            let candidate = directory.join(name);
            if candidate.is_file() {
                let config = Self::from_path(&candidate)?;
                return Ok(Some((candidate, config)));
            }
        }
        Ok(None)
    }

    /// Validate every setting before any analysis runs.
    ///
    /// Values that only make sense in a later command are still checked here,
    /// so a bad policy, network, endpoint, or CI status fails at load time.
    fn validate(&self) -> Result<()> {
        self.audit.validate()?;
        parse_compatibility_policy(&self.analysis.compatibility.policy)?;
        if let Some(network) = &self.project.network {
            let _ = network.parse::<Network>()?;
        }
        if let Some(endpoint) = &self.rpc.endpoint {
            let _ = observatory_rpc::Endpoint::parse(endpoint)?;
        }
        self.rpc_timeouts()?;
        self.rpc_max_response_bytes()?;
        self.ci.failure_statuses()?;
        for (name, profile) in &self.profiles {
            validate_profile_name(name)?;
            profile.validate()?;
        }
        self.selected_profile(None)?;
        Ok(())
    }

    /// Resolve the selected profile.
    ///
    /// `name` is the `--profile` flag; when it is absent the `profile` field
    /// applies. `None` means no profile was selected, so no overrides apply.
    pub fn selected_profile(&self, name: Option<&str>) -> Result<Option<&NetworkProfile>> {
        let Some(name) = name.or(self.profile.as_deref()) else {
            return Ok(None);
        };
        let network = name.parse::<Network>()?;
        self.profiles
            .iter()
            .find(|(profile, _)| {
                profile
                    .parse::<Network>()
                    .is_ok_and(|profile_network| profile_network == network)
            })
            .map(|(_, profile)| profile)
            .map(Some)
            .ok_or_else(|| {
                let known: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
                ObservatoryError::invalid(format!(
                    "unknown profile `{name}`; configured profiles: {}",
                    if known.is_empty() {
                        "<none>".to_string()
                    } else {
                        known.join(", ")
                    }
                ))
            })
    }

    /// Resolve the compatibility policy, applying a selected profile override.
    pub fn compatibility_policy_for(
        &self,
        profile: Option<&str>,
    ) -> Result<crate::CompatibilityPolicy> {
        if let Some(profile) = self.selected_profile(profile)? {
            if let Some(policy) = &profile.policy {
                return parse_compatibility_policy(policy);
            }
        }
        parse_compatibility_policy(&self.analysis.compatibility.policy)
    }

    /// Resolve the compatibility policy, validating the name.
    pub fn compatibility_policy(&self) -> Result<crate::CompatibilityPolicy> {
        parse_compatibility_policy(&self.analysis.compatibility.policy)
    }

    /// Resolve the RPC endpoint, applying a selected profile override.
    pub fn rpc_endpoint_for(&self, profile: Option<&str>) -> Result<Option<&str>> {
        match self.selected_profile(profile)? {
            Some(profile) if profile.endpoint.is_some() => Ok(profile.endpoint.as_deref()),
            _ => Ok(self.rpc.endpoint.as_deref()),
        }
    }

    /// Resolve RPC connect and read timeouts.
    ///
    /// Values are seconds; omitted values use the defaults in
    /// [`observatory_rpc::RpcTimeouts`]. A configured zero is rejected at load
    /// time rather than producing a transport that never connects.
    pub fn rpc_timeouts(&self) -> Result<observatory_rpc::RpcTimeouts> {
        observatory_rpc::RpcTimeouts::from_secs(
            self.rpc
                .connect_timeout_secs
                .unwrap_or(observatory_rpc::DEFAULT_CONNECT_TIMEOUT.as_secs()),
            self.rpc
                .read_timeout_secs
                .unwrap_or(observatory_rpc::DEFAULT_READ_TIMEOUT.as_secs()),
        )
    }

    /// Resolve the maximum RPC response body size.
    ///
    /// The value defaults to [`observatory_rpc::DEFAULT_MAX_RESPONSE_BYTES`] and
    /// a configured zero is rejected at load time, because a zero-byte limit
    /// would reject every response.
    pub fn rpc_max_response_bytes(&self) -> Result<usize> {
        let limit = self
            .rpc
            .max_response_bytes
            .unwrap_or(observatory_rpc::DEFAULT_MAX_RESPONSE_BYTES);
        if limit == 0 {
            return Err(ObservatoryError::invalid(
                "RPC maximum response size must be greater than zero",
            ));
        }
        Ok(limit)
    }

    /// Resolve the CORS policy.
    #[must_use]
    pub fn cors(&self) -> crate::CorsConfig {
        crate::CorsConfig {
            allowed_origins: self.api.cors.allowed_origins.clone(),
            allowed_methods: self.api.cors.allowed_methods.clone(),
            allowed_headers: self.api.cors.allowed_headers.clone(),
        }
    }

    /// Resolve the rate-limit configuration.
    #[must_use]
    pub fn rate_limit(&self) -> RateLimitConfig {
        self.api
            .rate_limit
            .map(|section| RateLimitConfig {
                limit: section.limit,
                window_secs: section.window_secs,
            })
            .unwrap_or_default()
    }

    /// Resolve per-route rate-limit overrides, keyed by exact request path.
    #[must_use]
    pub fn route_limits(&self) -> BTreeMap<String, RateLimitConfig> {
        self.api
            .route_limits
            .iter()
            .map(|(path, section)| {
                (
                    path.clone(),
                    RateLimitConfig {
                        limit: section.limit,
                        window_secs: section.window_secs,
                    },
                )
            })
            .collect()
    }

    /// Resolve the default network label, if configured.
    pub fn network(&self) -> Option<&str> {
        self.project.network.as_deref()
    }
}

/// Parse a role name (re-exported convenience for configuration-driven setups).
pub fn parse_role(value: &str) -> Result<Role> {
    value
        .parse()
        .map_err(|error: String| ObservatoryError::invalid(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yaml_json_and_toml() {
        let yaml = "project:\n  name: demo\n  network: testnet\nanalysis:\n  compatibility:\n    policy: lenient\n";
        let config = ProjectConfig::parse(yaml, ConfigFormat::Yaml).unwrap();
        assert_eq!(config.project.name.as_deref(), Some("demo"));
        assert_eq!(config.network(), Some("testnet"));
        assert!(
            !config
                .compatibility_policy()
                .unwrap()
                .function_removal_is_breaking
        );

        let json = r#"{ "project": { "network": "public" } }"#;
        let config = ProjectConfig::parse(json, ConfigFormat::Json).unwrap();
        assert_eq!(config.network(), Some("public"));

        let toml = "[api]\nrequire_auth = false\n[api.rate_limit]\nlimit = 5\nwindow_secs = 30\n";
        let config = ProjectConfig::parse(toml, ConfigFormat::Toml).unwrap();
        assert!(!config.api.require_auth);
        assert_eq!(config.rate_limit().limit, 5);
        assert_eq!(config.rate_limit().window_secs, 30);
    }

    #[test]
    fn resolves_the_additive_only_policy_preset() {
        let config = ProjectConfig::parse(
            "analysis:\n  compatibility:\n    policy: additive-only\nprofiles:\n  public:\n    policy: additive_only\n",
            ConfigFormat::Yaml,
        )
        .unwrap();
        assert_eq!(
            config.compatibility_policy().unwrap(),
            crate::CompatibilityPolicy::additive_only()
        );
        assert_eq!(
            config.compatibility_policy_for(Some("public")).unwrap(),
            crate::CompatibilityPolicy::additive_only()
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = ProjectConfig::parse("project:\n  nope: 1\n", ConfigFormat::Yaml).unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));
    }

    #[test]
    fn resolves_cors_allow_list() {
        let yaml = "api:\n  cors:\n    allowed_origins:\n      - https://app.example.com\n";
        let config = ProjectConfig::parse(yaml, ConfigFormat::Yaml).unwrap();
        assert!(config.cors().is_allowed_origin("https://app.example.com"));
        assert!(!config.cors().is_allowed_origin("https://evil.example.com"));
    }

    #[test]
    fn rejects_unknown_policy() {
        let error = ProjectConfig::parse(
            "analysis:\n  compatibility:\n    policy: wild\n",
            ConfigFormat::Yaml,
        )
        .unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));
        assert!(error.to_string().contains("unknown compatibility policy"));
    }

    #[test]
    fn rejects_invalid_network_endpoint_and_ci_status_before_analysis() {
        for yaml in [
            "project:\n  network: devnet\n",
            "rpc:\n  endpoint: not-a-url\n",
            "ci:\n  fail_on: MAYBE\n",
            "ci:\n  fail_on: MATCH\n",
        ] {
            let error = ProjectConfig::parse(yaml, ConfigFormat::Yaml).unwrap_err();
            assert!(matches!(error, ObservatoryError::InvalidInput(_)), "{yaml}");
        }
    }

    #[test]
    fn accepts_valid_network_endpoint_and_ci_status() {
        let config = ProjectConfig::parse(
            "project:\n  network: testnet\n\
             rpc:\n  endpoint: https://soroban-testnet.stellar.org\n\
             ci:\n  fail_on: MISMATCH, ERROR\n",
            ConfigFormat::Yaml,
        )
        .unwrap();
        assert_eq!(config.network(), Some("testnet"));
        assert_eq!(
            config.rpc_endpoint_for(None).unwrap(),
            Some("https://soroban-testnet.stellar.org")
        );
        assert_eq!(
            config.ci.failure_statuses().unwrap(),
            ["ERROR", "MISMATCH"].map(str::to_string).into()
        );
    }

    #[test]
    fn rpc_timeouts_default_and_parse() {
        let config = ProjectConfig::parse("{}", ConfigFormat::Yaml).unwrap();
        assert_eq!(
            config.rpc_timeouts().unwrap(),
            observatory_rpc::RpcTimeouts::default()
        );

        let config = ProjectConfig::parse(
            "rpc:\n  connect_timeout_secs: 3\n  read_timeout_secs: 7\n",
            ConfigFormat::Yaml,
        )
        .unwrap();
        let timeouts = config.rpc_timeouts().unwrap();
        assert_eq!(timeouts.connect, std::time::Duration::from_secs(3));
        assert_eq!(timeouts.read, std::time::Duration::from_secs(7));
    }

    #[test]
    fn rejects_zero_rpc_timeouts() {
        for yaml in [
            "rpc:\n  connect_timeout_secs: 0\n",
            "rpc:\n  read_timeout_secs: 0\n",
        ] {
            let error = ProjectConfig::parse(yaml, ConfigFormat::Yaml).unwrap_err();
            assert!(matches!(error, ObservatoryError::InvalidInput(_)), "{yaml}");
            assert!(error.to_string().contains("timeout"), "{error}");
        }
    }

    #[test]
    fn rpc_max_response_bytes_defaults_and_rejects_zero() {
        let config = ProjectConfig::parse("{}", ConfigFormat::Yaml).unwrap();
        assert_eq!(
            config.rpc_max_response_bytes().unwrap(),
            observatory_rpc::DEFAULT_MAX_RESPONSE_BYTES
        );

        let config =
            ProjectConfig::parse("rpc:\n  max_response_bytes: 4096\n", ConfigFormat::Yaml).unwrap();
        assert_eq!(config.rpc_max_response_bytes().unwrap(), 4096);

        let error = ProjectConfig::parse("rpc:\n  max_response_bytes: 0\n", ConfigFormat::Yaml)
            .unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));
        assert!(error.to_string().contains("response size"), "{error}");
    }

    #[test]
    fn infers_format_from_extension() {
        assert_eq!(
            ConfigFormat::from_path(Path::new("observatory.yml")).unwrap(),
            ConfigFormat::Yaml
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("observatory.toml")).unwrap(),
            ConfigFormat::Toml
        );
        assert!(ConfigFormat::from_path(Path::new("observatory.txt")).is_err());
    }
}
