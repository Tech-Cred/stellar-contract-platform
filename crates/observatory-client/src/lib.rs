//! Typed, blocking Rust client for the Stellar Contract Observatory REST API.
//!
//! The client reuses the published report and model types from the engine
//! crates, so callers get the same strongly typed results as the CLI. It
//! depends on the HTTP contract only, never on the server implementation.
//!
//! ```no_run
//! use observatory_client::Client;
//!
//! # fn main() -> Result<(), observatory_client::ClientError> {
//! let client = Client::builder("http://127.0.0.1:8080")
//!     .api_key("sco_...")
//!     .build()?;
//! let wasm = std::fs::read("contract.wasm").expect("read artifact");
//! let report = client.inspect(&wasm, false)?;
//! println!("{}", report.wasm.artifact_sha256);
//! # Ok(())
//! # }
//! ```
//!
//! Requests are bounded: artifacts larger than the engine limit are rejected
//! before encoding, and response bodies are capped. Redirects are not followed.

use std::time::Duration;

use base64::Engine as _;
use observatory_audit::AuditReport;
use observatory_compat::CompatibilityAssessment;
use observatory_core::hash::HashAlgorithm;
use observatory_core::limits::MAX_WASM_BYTES;
use observatory_diff::InterfaceDiff;
use observatory_interface::ContractInterface;
use observatory_output::Report;
use observatory_spec::{ContractSpec, SpecReport};
use observatory_wasm::WasmReport;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;

/// Default per-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum response body size (8 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A typed error returned by the client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The API returned a non-success status with a stable error code.
    #[error("API returned HTTP {status} ({code}): {message}")]
    Api {
        /// HTTP status.
        status: u16,
        /// Stable API error code.
        code: ApiErrorCode,
        /// Human-readable message.
        message: String,
        /// JSON-RPC failure kind, when the upstream error came from RPC.
        rpc_kind: Option<String>,
        /// Raw JSON-RPC code, when present.
        rpc_code: Option<i64>,
    },
    /// The request exceeded the configured timeout.
    #[error("request timed out")]
    Timeout,
    /// The response exceeded the configured body limit.
    #[error("response exceeded the {0} byte limit")]
    ResponseTooLarge(usize),
    /// The artifact exceeded the engine limit.
    #[error("artifact is {size} bytes, exceeding the {limit} byte limit")]
    RequestTooLarge {
        /// Artifact size.
        size: usize,
        /// Maximum accepted size.
        limit: usize,
    },
    /// The transport failed (DNS, TLS, connection, protocol).
    #[error("transport error: {0}")]
    Transport(String),
    /// The response body was not the expected JSON shape.
    #[error("could not decode response: {0}")]
    Decode(String),
    /// The client configuration is invalid.
    #[error("invalid client configuration: {0}")]
    Config(String),
}

/// Stable API and engine error codes returned by the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiErrorCode {
    /// Request validation failed.
    BadRequest,
    /// Missing or invalid API key.
    Unauthorized,
    /// The key lacks the required permission.
    Forbidden,
    /// Unknown route.
    NotFound,
    /// Known route with the wrong method.
    MethodNotAllowed,
    /// Non-JSON content type.
    UnsupportedMediaType,
    /// A feature is unsupported.
    UnprocessableEntity,
    /// Rate limit exceeded.
    RateLimited,
    /// Server-side failure.
    Internal,
    /// Engine: invalid input.
    InvalidInput,
    /// Engine: decode failure.
    Decode,
    /// Engine: malformed WASM.
    Wasm,
    /// Engine: malformed contract specification.
    Spec,
    /// Engine: unsupported feature.
    Unsupported,
    /// Engine: upstream RPC failure.
    Rpc,
    /// Engine: verification failure.
    Verification,
    /// Engine: I/O failure.
    Io,
    /// A code this client version does not know.
    Other(String),
}

impl ApiErrorCode {
    /// Map a wire code to a typed value.
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        match code {
            "bad_request" => ApiErrorCode::BadRequest,
            "unauthorized" => ApiErrorCode::Unauthorized,
            "forbidden" => ApiErrorCode::Forbidden,
            "not_found" => ApiErrorCode::NotFound,
            "method_not_allowed" => ApiErrorCode::MethodNotAllowed,
            "unsupported_media_type" => ApiErrorCode::UnsupportedMediaType,
            "unprocessable_entity" => ApiErrorCode::UnprocessableEntity,
            "rate_limited" => ApiErrorCode::RateLimited,
            "internal" => ApiErrorCode::Internal,
            "invalid_input" => ApiErrorCode::InvalidInput,
            "decode" => ApiErrorCode::Decode,
            "wasm" => ApiErrorCode::Wasm,
            "spec" => ApiErrorCode::Spec,
            "unsupported" => ApiErrorCode::Unsupported,
            "rpc" => ApiErrorCode::Rpc,
            "verification" => ApiErrorCode::Verification,
            "io" => ApiErrorCode::Io,
            other => ApiErrorCode::Other(other.to_string()),
        }
    }

    /// The wire code for this value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            ApiErrorCode::BadRequest => "bad_request",
            ApiErrorCode::Unauthorized => "unauthorized",
            ApiErrorCode::Forbidden => "forbidden",
            ApiErrorCode::NotFound => "not_found",
            ApiErrorCode::MethodNotAllowed => "method_not_allowed",
            ApiErrorCode::UnsupportedMediaType => "unsupported_media_type",
            ApiErrorCode::UnprocessableEntity => "unprocessable_entity",
            ApiErrorCode::RateLimited => "rate_limited",
            ApiErrorCode::Internal => "internal",
            ApiErrorCode::InvalidInput => "invalid_input",
            ApiErrorCode::Decode => "decode",
            ApiErrorCode::Wasm => "wasm",
            ApiErrorCode::Spec => "spec",
            ApiErrorCode::Unsupported => "unsupported",
            ApiErrorCode::Rpc => "rpc",
            ApiErrorCode::Verification => "verification",
            ApiErrorCode::Io => "io",
            ApiErrorCode::Other(code) => code,
        }
    }
}

impl std::fmt::Display for ApiErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Compatibility policy accepted by the compatibility endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Strict policy.
    Strict,
    /// Lenient policy.
    Lenient,
}

impl Policy {
    /// The wire value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Strict => "strict",
            Policy::Lenient => "lenient",
        }
    }
}

/// Health response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Health {
    /// Status, always `ok`.
    pub status: String,
}

/// Readiness probe response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Readiness {
    /// Status, always `ready`.
    pub status: String,
    /// Whether analysis endpoints require an API key.
    pub auth_required: bool,
}

/// Version response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VersionInfo {
    /// Tool name.
    pub tool: String,
    /// Tool version.
    pub version: String,
    /// Report schema version.
    pub schema_version: String,
    /// REST API version.
    pub api_version: String,
}

/// Inspection response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InspectResponse {
    /// WASM structure report.
    pub wasm: WasmReport,
    /// Canonical interface, when the artifact has a specification.
    pub interface: Option<ContractInterface>,
    /// Audit findings, when requested.
    pub audit: Option<AuditReport>,
}

/// Specification response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SpecResponse {
    /// Normalized contract specification.
    pub spec: ContractSpec,
    /// Counts and validation issues.
    pub summary: SpecReport,
}

/// Fingerprint response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FingerprintResponse {
    /// Artifact digest.
    ///
    /// The field name is kept for compatibility; `algorithm` says which digest
    /// produced it. The default is SHA-256.
    pub artifact_sha256: String,
    /// Canonical interface digest, when a specification is present.
    ///
    /// The field name is kept for compatibility; `algorithm` says which digest
    /// produced it. The default is SHA-256.
    pub interface_sha256: Option<String>,
    /// Hash algorithm used for both digests.
    #[serde(default)]
    pub algorithm: HashAlgorithm,
}

/// A typed Observatory API client.
#[derive(Debug)]
pub struct Client {
    base_url: String,
    api_key: Option<String>,
    agent: ureq::Agent,
    max_response_bytes: usize,
}

/// Builder for [`Client`].
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    base_url: String,
    api_key: Option<String>,
    timeout: Duration,
    max_response_bytes: usize,
}

impl ClientBuilder {
    /// Authenticate with an API key (`X-API-Key`).
    #[must_use]
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set the per-request timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum accepted response body size.
    #[must_use]
    pub fn max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = limit;
        self
    }

    /// Validate the configuration and build the client.
    pub fn build(self) -> Result<Client, ClientError> {
        if self.timeout.is_zero() {
            return Err(ClientError::Config(
                "timeout must be greater than zero".to_string(),
            ));
        }
        if self.max_response_bytes == 0 {
            return Err(ClientError::Config(
                "maximum response size must be greater than zero".to_string(),
            ));
        }
        let base_url = self.base_url.trim_end_matches('/').to_string();
        if base_url.is_empty()
            || !(base_url.starts_with("http://") || base_url.starts_with("https://"))
        {
            return Err(ClientError::Config(
                "base URL must start with http:// or https://".to_string(),
            ));
        }
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .build();
        Ok(Client {
            base_url,
            api_key: self.api_key,
            agent: ureq::Agent::new_with_config(config),
            max_response_bytes: self.max_response_bytes,
        })
    }
}

impl Client {
    /// Create a client with the default timeout and response limit.
    pub fn new(base_url: impl Into<String>) -> Result<Client, ClientError> {
        Client::builder(base_url).build()
    }

    /// Start configuring a client.
    #[must_use]
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base_url: base_url.into(),
            api_key: None,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// The configured base URL, without a trailing slash.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch the readiness probe.
    pub fn health(&self) -> Result<Health, ClientError> {
        self.get("health", "/api/v1/health")
    }

    /// Fetch the readiness probe.
    pub fn readiness(&self) -> Result<Readiness, ClientError> {
        self.get("readiness", "/api/v1/readiness")
    }

    /// Fetch tool and API versions.
    pub fn version(&self) -> Result<VersionInfo, ClientError> {
        self.get("version", "/api/v1/version")
    }

    /// Inspect a WASM artifact without executing it.
    pub fn inspect(&self, wasm: &[u8], security: bool) -> Result<InspectResponse, ClientError> {
        let body = serde_json::json!({
            "wasm_base64": encode_wasm(wasm)?,
            "security": security,
        });
        self.send("inspect", "POST", "/api/v1/contracts/inspect", Some(&body))
    }

    /// Read the contract specification.
    pub fn spec(&self, wasm: &[u8]) -> Result<SpecResponse, ClientError> {
        let body = serde_json::json!({ "wasm_base64": encode_wasm(wasm)? });
        self.send("spec", "POST", "/api/v1/contracts/spec", Some(&body))
    }

    /// Diff two contract interfaces.
    pub fn diff(&self, old: &[u8], new: &[u8]) -> Result<InterfaceDiff, ClientError> {
        let body = serde_json::json!({
            "old_wasm_base64": encode_wasm(old)?,
            "new_wasm_base64": encode_wasm(new)?,
        });
        self.send("diff", "POST", "/api/v1/contracts/diff", Some(&body))
    }

    /// Assess compatibility of two contract interfaces.
    pub fn compatibility(
        &self,
        old: &[u8],
        new: &[u8],
        policy: Policy,
    ) -> Result<CompatibilityAssessment, ClientError> {
        let body = serde_json::json!({
            "old_wasm_base64": encode_wasm(old)?,
            "new_wasm_base64": encode_wasm(new)?,
            "policy": policy.as_str(),
        });
        self.send(
            "compat",
            "POST",
            "/api/v1/contracts/compatibility",
            Some(&body),
        )
    }

    /// Compute artifact and interface fingerprints with the default SHA-256.
    pub fn fingerprint(&self, wasm: &[u8]) -> Result<FingerprintResponse, ClientError> {
        self.fingerprint_with(wasm, HashAlgorithm::Sha256)
    }

    /// Compute artifact and interface fingerprints with `algorithm`.
    pub fn fingerprint_with(
        &self,
        wasm: &[u8],
        algorithm: HashAlgorithm,
    ) -> Result<FingerprintResponse, ClientError> {
        let body = serde_json::json!({
            "wasm_base64": encode_wasm(wasm)?,
            "algorithm": algorithm.as_str(),
        });
        self.send(
            "fingerprint",
            "POST",
            "/api/v1/contracts/fingerprint",
            Some(&body),
        )
    }

    /// Run bounded security heuristics.
    pub fn security(&self, wasm: &[u8]) -> Result<AuditReport, ClientError> {
        let body = serde_json::json!({ "wasm_base64": encode_wasm(wasm)? });
        self.send(
            "security",
            "POST",
            "/api/v1/contracts/security",
            Some(&body),
        )
    }

    fn get<T: DeserializeOwned>(&self, kind: &str, path: &str) -> Result<T, ClientError> {
        self.send(kind, "GET", path, None)
    }

    fn send<T: DeserializeOwned>(
        &self,
        kind: &str,
        _method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T, ClientError> {
        let url = format!("{}{path}", self.base_url);
        let response = match body {
            Some(value) => {
                let body = serde_json::to_vec(value).map_err(|error| {
                    ClientError::Decode(format!("cannot encode request body: {error}"))
                })?;
                self.authorize(self.agent.post(&url))
                    .header("content-type", "application/json")
                    .send(body)
            }
            None => self.authorize(self.agent.get(&url)).call(),
        }
        .map_err(|error| self.transport_error(&error))?;

        let status = response.status().as_u16();
        let mut response = response;
        let bytes = response
            .body_mut()
            .with_config()
            .limit(self.max_response_bytes as u64)
            .read_to_vec()
            .map_err(|error| self.transport_error(&error))?;

        if !(200..300).contains(&status) {
            return Err(api_error(status, &bytes));
        }

        let envelope: Report<T> = serde_json::from_slice(&bytes).map_err(|error| {
            ClientError::Decode(format!("invalid `{kind}` report envelope: {error}"))
        })?;
        if envelope.kind != kind {
            return Err(ClientError::Decode(format!(
                "expected kind `{kind}`, got `{}`",
                envelope.kind
            )));
        }
        Ok(envelope.data)
    }

    fn authorize<B>(&self, request: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        let request = match &self.api_key {
            Some(key) => request.header("x-api-key", key),
            None => request,
        };
        request.header("accept", "application/json")
    }

    fn transport_error(&self, error: &ureq::Error) -> ClientError {
        match error {
            ureq::Error::Timeout(_) => ClientError::Timeout,
            ureq::Error::BodyExceedsLimit(_) => {
                ClientError::ResponseTooLarge(self.max_response_bytes)
            }
            other => ClientError::Transport(other.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    rpc_kind: Option<String>,
    #[serde(default)]
    rpc_code: Option<i64>,
}

fn api_error(status: u16, body: &[u8]) -> ClientError {
    match serde_json::from_slice::<ApiErrorBody>(body) {
        Ok(error) => ClientError::Api {
            status,
            code: ApiErrorCode::from_code(&error.code),
            message: error.message,
            rpc_kind: error.rpc_kind,
            rpc_code: error.rpc_code,
        },
        Err(_) => ClientError::Api {
            status,
            code: ApiErrorCode::Other(String::new()),
            message: String::from_utf8_lossy(body).into_owned(),
            rpc_kind: None,
            rpc_code: None,
        },
    }
}

fn encode_wasm(wasm: &[u8]) -> Result<String, ClientError> {
    if wasm.len() > MAX_WASM_BYTES {
        return Err(ClientError::RequestTooLarge {
            size: wasm.len(),
            limit: MAX_WASM_BYTES,
        });
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(wasm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_configuration() {
        assert!(matches!(
            Client::builder("ftp://example.invalid").build(),
            Err(ClientError::Config(_))
        ));
        assert!(matches!(
            Client::builder("http://127.0.0.1")
                .timeout(Duration::ZERO)
                .build(),
            Err(ClientError::Config(_))
        ));
        assert!(matches!(
            Client::builder("http://127.0.0.1")
                .max_response_bytes(0)
                .build(),
            Err(ClientError::Config(_))
        ));
    }

    #[test]
    fn maps_wire_error_codes() {
        assert_eq!(
            ApiErrorCode::from_code("rate_limited"),
            ApiErrorCode::RateLimited
        );
        assert_eq!(ApiErrorCode::from_code("wasm").as_str(), "wasm");
        assert_eq!(
            ApiErrorCode::from_code("custom"),
            ApiErrorCode::Other("custom".to_string())
        );
    }

    #[test]
    fn base_url_drops_a_trailing_slash() {
        let client = Client::new("http://127.0.0.1:8080/").unwrap();
        assert_eq!(client.base_url(), "http://127.0.0.1:8080");
    }
}
