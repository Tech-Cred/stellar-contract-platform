//! Stellar RPC transport abstraction and typed models.
//!
//! The core never hard-codes a provider. A [`Transport`] moves JSON-RPC
//! envelopes; [`RpcClient`] builds requests, normalizes errors, and returns
//! typed responses. [`MockTransport`] provides deterministic responses so tests
//! never touch the network.
//!
//! Only methods with a stable, documented shape are modelled here. Anything not
//! modelled is intentionally absent rather than guessed.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use observatory_core::{ObservatoryError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use stellar_xdr::{LedgerEntryData, Limits, ReadXdr, ScVal};

pub mod net;

#[cfg(feature = "live")]
pub mod live;

#[cfg(feature = "live")]
pub use live::{HttpTransport, DEFAULT_TIMEOUT};
pub use net::{AddressClass, SsrfPolicy};
pub use observatory_core::{RpcError, RpcErrorKind};

/// Default maximum RPC response body size (8 MiB).
///
/// The live transport rejects a larger body before parsing it, so a hostile or
/// misconfigured endpoint cannot exhaust memory.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum events accepted in a single `getEvents` page.
pub const MAX_EVENTS_PAGE: usize = 10_000;

/// Default maximum number of attempts for a retried RPC call.
pub const DEFAULT_MAX_RETRY_ATTEMPTS: u32 = 3;

/// Default delay before the first retry.
pub const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_millis(200);

/// Default cap on the delay between retries.
pub const DEFAULT_RETRY_MAX_DELAY: Duration = Duration::from_secs(2);

/// A JSON-RPC transport. Implementations move already-built envelopes.
pub trait Transport {
    /// Send a JSON-RPC request envelope and return the response envelope.
    fn send(&self, request: &Value) -> Result<Value>;
}

/// A blocking clock, injectable so retry tests never wait.
pub trait Clock {
    /// Sleep for `duration`.
    fn sleep(&self, duration: Duration);
}

/// The wall clock, used outside tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// A bounded retry policy for transient RPC failures.
///
/// Only transport failures and server-side JSON-RPC errors
/// ([`RpcErrorKind::Transport`], [`RpcErrorKind::Internal`], and
/// [`RpcErrorKind::Server`]) are retried. Client errors such as invalid
/// parameters or an unknown method are returned immediately: retrying them
/// cannot succeed. Delays grow exponentially from
/// [`RetryPolicy::base_delay`], are capped at [`RetryPolicy::max_delay`], and
/// the total number of attempts is bounded by [`RetryPolicy::max_attempts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: DEFAULT_MAX_RETRY_ATTEMPTS,
            base_delay: DEFAULT_RETRY_BASE_DELAY,
            max_delay: DEFAULT_RETRY_MAX_DELAY,
        }
    }
}

impl RetryPolicy {
    /// Build a policy, rejecting zero attempts, delays, or a cap below the base.
    pub fn new(max_attempts: u32, base_delay: Duration, max_delay: Duration) -> Result<Self> {
        if max_attempts == 0 {
            return Err(ObservatoryError::invalid(
                "RPC retry attempts must be greater than zero",
            ));
        }
        if base_delay.is_zero() {
            return Err(ObservatoryError::invalid(
                "RPC retry base delay must be greater than zero",
            ));
        }
        if max_delay < base_delay {
            return Err(ObservatoryError::invalid(
                "RPC retry maximum delay must not be smaller than the base delay",
            ));
        }
        Ok(RetryPolicy {
            max_attempts,
            base_delay,
            max_delay,
        })
    }

    /// The maximum number of attempts, including the first.
    #[must_use]
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// The delay before the first retry.
    #[must_use]
    pub fn base_delay(&self) -> Duration {
        self.base_delay
    }

    /// The delay cap.
    #[must_use]
    pub fn max_delay(&self) -> Duration {
        self.max_delay
    }

    /// The delay after failed attempt `attempt` (1-based): `base * 2^(n-1)`.
    #[must_use]
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let factor = 1u32 << attempt.saturating_sub(1).min(31);
        self.base_delay.saturating_mul(factor).min(self.max_delay)
    }
}

/// Whether a failure is transient and safe to retry.
///
/// Only transport failures and server-side JSON-RPC codes are retryable;
/// client errors and non-RPC errors are not.
#[must_use]
pub fn is_retryable(error: &ObservatoryError) -> bool {
    match error {
        ObservatoryError::Rpc(error) => matches!(
            error.kind(),
            RpcErrorKind::Transport | RpcErrorKind::Internal | RpcErrorKind::Server
        ),
        _ => false,
    }
}

/// Run `operation` under a bounded retry policy, sleeping on `clock` between
/// attempts.
///
/// `operation` receives the 1-based attempt number. The first non-retryable
/// error, or the error from the final attempt, is returned unchanged.
pub fn retry_call<T>(
    policy: &RetryPolicy,
    clock: &dyn Clock,
    mut operation: impl FnMut(u32) -> Result<T>,
) -> Result<T> {
    let mut attempt = 1;
    loop {
        match operation(attempt) {
            Ok(value) => return Ok(value),
            Err(error) if attempt < policy.max_attempts && is_retryable(&error) => {
                clock.sleep(policy.delay_for(attempt));
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Default timeout for establishing a TCP/TLS connection.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for receiving response headers and the response body.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect and read timeouts for an RPC transport.
///
/// A timeout is per request: the connect budget covers DNS, TCP, and TLS
/// setup, and the read budget covers waiting for response headers and reading
/// the body. Exceeding either budget fails the request with an
/// [`ObservatoryError::Rpc`] error; it is never retried implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcTimeouts {
    /// Maximum time to establish a connection.
    pub connect: Duration,
    /// Maximum time to wait for and read a response.
    pub read: Duration,
}

impl Default for RpcTimeouts {
    fn default() -> Self {
        RpcTimeouts {
            connect: DEFAULT_CONNECT_TIMEOUT,
            read: DEFAULT_READ_TIMEOUT,
        }
    }
}

impl RpcTimeouts {
    /// Build timeouts, rejecting zero values.
    pub fn new(connect: Duration, read: Duration) -> Result<Self> {
        if connect.is_zero() {
            return Err(ObservatoryError::invalid(
                "RPC connect timeout must be greater than zero",
            ));
        }
        if read.is_zero() {
            return Err(ObservatoryError::invalid(
                "RPC read timeout must be greater than zero",
            ));
        }
        Ok(RpcTimeouts { connect, read })
    }

    /// Build timeouts from whole seconds, rejecting zero values.
    pub fn from_secs(connect_secs: u64, read_secs: u64) -> Result<Self> {
        RpcTimeouts::new(
            Duration::from_secs(connect_secs),
            Duration::from_secs(read_secs),
        )
    }
}

impl<T: Transport + ?Sized> Transport for &T {
    fn send(&self, request: &Value) -> Result<Value> {
        (**self).send(request)
    }
}

/// A validated RPC endpoint URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    url: String,
    host: String,
    loopback: bool,
}

impl Endpoint {
    /// Parse and validate an endpoint.
    ///
    /// Rules: `https` is required except for loopback hosts, and embedded
    /// credentials are rejected.
    pub fn parse(input: &str) -> Result<Self> {
        let url = input.trim();
        if url.is_empty() {
            return Err(ObservatoryError::invalid("empty RPC endpoint"));
        }
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| ObservatoryError::invalid("RPC endpoint is missing a scheme"))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "https" && scheme != "http" {
            return Err(ObservatoryError::invalid(format!(
                "unsupported endpoint scheme `{scheme}`; expected https"
            )));
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() {
            return Err(ObservatoryError::invalid("RPC endpoint is missing a host"));
        }
        if authority.contains('@') {
            return Err(ObservatoryError::invalid(
                "RPC endpoint must not embed credentials",
            ));
        }
        let host = if let Some(stripped) = authority.strip_prefix('[') {
            stripped
                .split_once(']')
                .map(|(host, _)| host.to_string())
                .ok_or_else(|| ObservatoryError::invalid("malformed IPv6 host in endpoint"))?
        } else {
            authority.split(':').next().unwrap_or(authority).to_string()
        };
        if host.is_empty() {
            return Err(ObservatoryError::invalid("RPC endpoint is missing a host"));
        }
        let lower = host.to_ascii_lowercase();
        let loopback = matches!(lower.as_str(), "localhost" | "127.0.0.1" | "::1")
            || lower.ends_with(".localhost");
        if scheme == "http" && !loopback {
            return Err(ObservatoryError::invalid(
                "plain http is only allowed for loopback endpoints",
            ));
        }
        Ok(Endpoint {
            url: url.to_string(),
            host,
            loopback,
        })
    }

    /// The endpoint as provided.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// The parsed host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether the host is a loopback address.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.loopback
    }

    /// The effective port, using scheme defaults when omitted.
    #[must_use]
    pub fn port(&self) -> u16 {
        let (scheme, rest) = self.url.split_once("://").unwrap_or(("", ""));
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let default = if scheme.eq_ignore_ascii_case("http") {
            80
        } else {
            443
        };
        if let Some(stripped) = authority.strip_prefix('[') {
            if let Some((_, after)) = stripped.split_once(']') {
                if let Some(port) = after.strip_prefix(':').and_then(|p| p.parse().ok()) {
                    return port;
                }
            }
            return default;
        }
        authority
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or(default)
    }

    /// Validate the endpoint host against the SSRF policy.
    ///
    /// A live transport must call this before connecting.
    pub fn validate_ssrf(&self, policy: &SsrfPolicy) -> Result<Vec<std::net::IpAddr>> {
        policy.validate(&self.host, self.port())
    }
}

/// Latest ledger information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestLedger {
    /// Ledger sequence.
    pub sequence: u32,
    /// Ledger hash/id, when provided.
    pub id: Option<String>,
    /// Protocol version, when provided.
    pub protocol_version: Option<u32>,
}

/// Network information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Network passphrase.
    pub passphrase: String,
    /// Protocol version, when provided.
    pub protocol_version: Option<u32>,
}

/// One ledger entry returned by `getLedgerEntries`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntryResult {
    /// Base64 XDR of the ledger key.
    pub key: String,
    /// Base64 XDR of the ledger entry data.
    pub xdr: String,
    /// Last modified ledger sequence.
    pub last_modified_ledger_seq: Option<u32>,
    /// Live-until ledger sequence.
    pub live_until_ledger_seq: Option<u32>,
}

/// The contract-data durability keyspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Durability {
    /// Persistent storage, the default.
    #[default]
    Persistent,
    /// Temporary storage, which may expire.
    Temporary,
}

impl Durability {
    /// The wire value used by `getContractData`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Durability::Persistent => "persistent",
            Durability::Temporary => "temporary",
        }
    }
}

/// A request for `getContractData`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetContractDataRequest {
    /// Contract id (a `C...` strkey).
    pub contract_id: String,
    /// Base64 XDR of the `ScVal` storage key.
    pub key: String,
    /// The durability keyspace to read from.
    #[serde(default)]
    pub durability: Durability,
}

impl GetContractDataRequest {
    /// Build a request against the persistent keyspace.
    #[must_use]
    pub fn new(contract_id: impl Into<String>, key: impl Into<String>) -> Self {
        GetContractDataRequest {
            contract_id: contract_id.into(),
            key: key.into(),
            durability: Durability::Persistent,
        }
    }

    /// Read from a different durability keyspace.
    #[must_use]
    pub fn with_durability(mut self, durability: Durability) -> Self {
        self.durability = durability;
        self
    }
}

/// A single contract-data entry returned by `getContractData`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractDataResult {
    /// Base64 XDR of the `LedgerEntryData`.
    pub xdr: String,
    /// Last modified ledger sequence.
    pub last_modified_ledger_seq: Option<u32>,
    /// Live-until ledger sequence.
    pub live_until_ledger_seq: Option<u32>,
    /// Sequence of the latest ledger known to the server.
    pub latest_ledger: Option<u32>,
}

/// One page of contract events returned by `getEvents`.
///
/// Events are kept as raw JSON so the events crate owns normalization; the
/// client still validates the envelope and bounds the page size.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventsPage {
    /// Raw event objects from the RPC response.
    pub events: Vec<Value>,
    /// Opaque cursor for the next page, when the server returns one.
    pub cursor: Option<String>,
    /// Latest ledger known to the server.
    pub latest_ledger: Option<u32>,
    /// Oldest ledger the server still retains events for.
    pub oldest_ledger: Option<u32>,
}

/// The result of the documented `getHealth` method.
///
/// Fields mirror the published RPC schema exactly: `status`, both ledger
/// sequences, both close times as Unix timestamp strings, and the configured
/// retention window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResult {
    /// Reported node status, `"healthy"` on a healthy endpoint.
    pub status: String,
    /// Most recent known ledger sequence.
    pub latest_ledger: u32,
    /// Unix timestamp (as a string) of the latest ledger close.
    pub latest_ledger_close_time: String,
    /// Oldest ledger sequence kept in history.
    pub oldest_ledger: u32,
    /// Unix timestamp (as a string) of the oldest ledger close.
    pub oldest_ledger_close_time: String,
    /// Maximum configured ledger retention window.
    pub ledger_retention_window: u32,
}

/// A typed RPC client over a [`Transport`].
#[derive(Debug, Clone)]
pub struct RpcClient<T: Transport> {
    endpoint: Endpoint,
    transport: T,
}

impl<T: Transport> RpcClient<T> {
    /// Create a client.
    pub fn new(endpoint: Endpoint, transport: T) -> Self {
        RpcClient {
            endpoint,
            transport,
        }
    }

    /// The endpoint in use.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Call a JSON-RPC method and return its `result`, normalizing errors.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = self.transport.send(&request)?;
        if let Some(error) = response.get("error") {
            let code = error.get("code").and_then(Value::as_i64);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown RPC error");
            return Err(ObservatoryError::from_rpc_error(
                RpcError::from_optional_code(code, format!("{method} failed: {message}")),
            ));
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| ObservatoryError::rpc(format!("{method} response had no result")))
    }

    /// Call a JSON-RPC method under a bounded [`RetryPolicy`].
    ///
    /// Only transient failures are retried; see [`is_retryable`]. The clock is
    /// injected so tests are deterministic and do not sleep.
    pub fn call_with_retry(
        &self,
        method: &str,
        params: Value,
        policy: &RetryPolicy,
        clock: &dyn Clock,
    ) -> Result<Value> {
        retry_call(policy, clock, |_| self.call(method, params.clone()))
    }

    /// Fetch the latest ledger.
    pub fn get_latest_ledger(&self) -> Result<LatestLedger> {
        let result = self.call("getLatestLedger", json!({}))?;
        Ok(LatestLedger {
            sequence: result.get("sequence").and_then(Value::as_u64).unwrap_or(0) as u32,
            id: result.get("id").and_then(Value::as_str).map(str::to_string),
            protocol_version: result
                .get("protocolVersion")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
        })
    }

    /// Fetch network information.
    pub fn get_network(&self) -> Result<NetworkInfo> {
        let result = self.call("getNetwork", json!({}))?;
        Ok(NetworkInfo {
            passphrase: result
                .get("passphrase")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            protocol_version: result
                .get("protocolVersion")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
        })
    }

    /// Fetch endpoint health with the documented `getHealth` method.
    ///
    /// A malformed or incomplete result is a decode error rather than a
    /// partially-filled health report; no fields are invented.
    pub fn get_health(&self) -> Result<HealthResult> {
        let result = self.call("getHealth", json!({}))?;
        serde_json::from_value(result).map_err(|error| {
            ObservatoryError::decode(format!("invalid getHealth response: {error}"))
        })
    }

    /// Fetch ledger entries for base64-XDR keys.
    pub fn get_ledger_entries(&self, keys: &[String]) -> Result<Vec<LedgerEntryResult>> {
        let result = self.call("getLedgerEntries", json!({ "keys": keys }))?;
        let entries = result
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ObservatoryError::rpc("getLedgerEntries response had no entries array")
            })?;
        Ok(entries
            .iter()
            .map(|entry| LedgerEntryResult {
                key: entry
                    .get("key")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                xdr: entry
                    .get("xdr")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                last_modified_ledger_seq: entry
                    .get("lastModifiedLedgerSeq")
                    .and_then(Value::as_u64)
                    .map(|value| value as u32),
                live_until_ledger_seq: entry
                    .get("liveUntilLedgerSeq")
                    .and_then(Value::as_u64)
                    .map(|value| value as u32),
            })
            .collect())
    }

    /// Fetch one contract-data ledger entry.
    ///
    /// The contract id must be a `C...` strkey and `request.key` must be base64
    /// XDR of an `ScVal`. The returned entry XDR is decoded and must be a
    /// contract-data entry, so an unexpected response is rejected instead of
    /// being passed on as opaque bytes.
    pub fn get_contract_data(
        &self,
        request: &GetContractDataRequest,
    ) -> Result<ContractDataResult> {
        validate_contract_id(&request.contract_id)?;
        let key = request.key.trim();
        if key.is_empty() {
            return Err(ObservatoryError::invalid(
                "contract data key must not be empty",
            ));
        }
        ScVal::from_xdr_base64(key, Limits::none()).map_err(|error| {
            ObservatoryError::invalid(format!("invalid contract data key XDR: {error}"))
        })?;

        let result = self.call(
            "getContractData",
            json!({
                "contractId": request.contract_id.trim(),
                "key": key,
                "durability": request.durability.as_str(),
            }),
        )?;
        let xdr = result
            .get("xdr")
            .and_then(Value::as_str)
            .ok_or_else(|| ObservatoryError::rpc("getContractData response had no xdr field"))?;
        let entry = LedgerEntryData::from_xdr_base64(xdr, Limits::none()).map_err(|error| {
            ObservatoryError::decode(format!("invalid contract data entry XDR: {error}"))
        })?;
        if !matches!(entry, LedgerEntryData::ContractData(_)) {
            return Err(ObservatoryError::decode(
                "getContractData response was not a contract data entry",
            ));
        }
        Ok(ContractDataResult {
            xdr: xdr.to_string(),
            last_modified_ledger_seq: result
                .get("lastModifiedLedgerSeq")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            live_until_ledger_seq: result
                .get("liveUntilLedgerSeq")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            latest_ledger: result
                .get("latestLedger")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
        })
    }

    /// Fetch one page of contract events via `getEvents`.
    ///
    /// Pagination is the caller's responsibility: pass
    /// `{"pagination": {"limit": n, "cursor": "..."}}` and use the returned
    /// [`EventsPage::cursor`] for the next request. The response is bounded to
    /// [`MAX_EVENTS_PAGE`] events before it is returned.
    pub fn get_events(&self, params: Value) -> Result<EventsPage> {
        let result = self.call("getEvents", params)?;
        let events = result
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| ObservatoryError::rpc("getEvents response had no events array"))?;
        if events.len() > MAX_EVENTS_PAGE {
            return Err(ObservatoryError::invalid(format!(
                "getEvents page has {} events, exceeding the {MAX_EVENTS_PAGE} limit",
                events.len()
            )));
        }
        Ok(EventsPage {
            events,
            cursor: result
                .get("cursor")
                .and_then(Value::as_str)
                .map(str::to_string),
            latest_ledger: result
                .get("latestLedger")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            oldest_ledger: result
                .get("oldestLedger")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
        })
    }
}

fn validate_contract_id(input: &str) -> Result<()> {
    let parsed = stellar_strkey::Strkey::from_string(input.trim())
        .map_err(|error| ObservatoryError::invalid(format!("invalid contract id: {error}")))?;
    if !matches!(parsed, stellar_strkey::Strkey::Contract(_)) {
        return Err(ObservatoryError::invalid(
            "provided strkey is not a contract id (expected a C... strkey)",
        ));
    }
    Ok(())
}

/// A deterministic in-memory transport for tests.
#[derive(Debug, Default)]
pub struct MockTransport {
    results: BTreeMap<String, Value>,
    errors: BTreeMap<String, Value>,
    sequences: RefCell<BTreeMap<String, VecDeque<Value>>>,
    calls: RefCell<Vec<String>>,
}

impl MockTransport {
    /// Create an empty mock transport.
    #[must_use]
    pub fn new() -> Self {
        MockTransport::default()
    }

    /// Register a successful result for a method.
    #[must_use]
    pub fn with_result(mut self, method: &str, result: Value) -> Self {
        self.results.insert(method.to_string(), result);
        self
    }

    /// Register a sequence of results returned in order for a method.
    ///
    /// Calls beyond the sequence fall back to [`MockTransport::with_result`].
    #[must_use]
    pub fn with_sequence(self, method: &str, results: Vec<Value>) -> Self {
        let queue: VecDeque<Value> = results.into_iter().collect();
        self.sequences
            .borrow_mut()
            .insert(method.to_string(), queue);
        self
    }

    /// Register an error for a method.
    #[must_use]
    pub fn with_error(mut self, method: &str, code: i64, message: &str) -> Self {
        self.errors.insert(
            method.to_string(),
            json!({ "code": code, "message": message }),
        );
        self
    }

    /// The methods called, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    /// Build a transport from a JSON object mapping method name to result.
    ///
    /// A value of the form `{ "__error": { "code": -32000, "message": "..." } }`
    /// registers an error response for that method.
    pub fn from_json(value: &Value) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| ObservatoryError::rpc("RPC fixture must be a JSON object"))?;
        let mut transport = MockTransport::new();
        for (method, result) in object {
            if let Some(sequence) = result.get("__sequence").and_then(Value::as_array) {
                transport = transport.with_sequence(method, sequence.clone());
            } else if let Some(error) = result.get("__error") {
                let code = error.get("code").and_then(Value::as_i64).unwrap_or(-32000);
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("error");
                transport = transport.with_error(method, code, message);
            } else {
                transport = transport.with_result(method, result.clone());
            }
        }
        Ok(transport)
    }
}

impl Transport for MockTransport {
    fn send(&self, request: &Value) -> Result<Value> {
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| ObservatoryError::rpc("mock request missing method"))?;
        self.calls.borrow_mut().push(method.to_string());
        if let Some(queue) = self.sequences.borrow_mut().get_mut(method) {
            if let Some(result) = queue.pop_front() {
                return Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": result }));
            }
        }
        if let Some(error) = self.errors.get(method) {
            return Ok(json!({ "jsonrpc": "2.0", "id": 1, "error": error.clone() }));
        }
        if let Some(result) = self.results.get(method) {
            return Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": result.clone() }));
        }
        Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32601, "message": format!("method not mocked: {method}") }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https() {
        let endpoint = Endpoint::parse("https://soroban-testnet.stellar.org").unwrap();
        assert_eq!(endpoint.host(), "soroban-testnet.stellar.org");
        assert!(!endpoint.is_loopback());
    }

    #[test]
    fn accepts_loopback_http() {
        assert!(Endpoint::parse("http://localhost:8000")
            .unwrap()
            .is_loopback());
        assert!(Endpoint::parse("http://127.0.0.1:8000")
            .unwrap()
            .is_loopback());
    }

    #[test]
    fn rejects_remote_http_and_credentials_and_schemes() {
        assert!(Endpoint::parse("http://example.com").is_err());
        assert!(Endpoint::parse("https://user:pass@example.com").is_err());
        assert!(Endpoint::parse("ftp://example.com").is_err());
        assert!(Endpoint::parse("not a url").is_err());
        assert!(Endpoint::parse("").is_err());
    }

    #[test]
    fn calls_typed_methods() {
        let transport = MockTransport::new()
            .with_result("getLatestLedger", json!({ "sequence": 42, "id": "abc" }))
            .with_result(
                "getNetwork",
                json!({ "passphrase": "Test SDF Network ; September 2015" }),
            )
            .with_result(
                "getLedgerEntries",
                json!({ "entries": [ { "key": "k", "xdr": "x", "lastModifiedLedgerSeq": 7 } ] }),
            );
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        assert_eq!(client.get_latest_ledger().unwrap().sequence, 42);
        assert!(client
            .get_network()
            .unwrap()
            .passphrase
            .contains("Test SDF"));
        let entries = client.get_ledger_entries(&["key".to_string()]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].last_modified_ledger_seq, Some(7));
        assert_eq!(
            client.endpoint,
            Endpoint::parse("https://example.org").unwrap()
        );
    }

    #[test]
    fn normalizes_rpc_errors() {
        let transport = MockTransport::new().with_error("getNetwork", -32601, "not found");
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let error = client.get_network().unwrap_err();
        assert!(matches!(error, ObservatoryError::Rpc(_)));
        assert!(error.to_string().contains("not found"));
        let rpc = error.rpc_error().expect("typed rpc error");
        assert_eq!(rpc.kind(), RpcErrorKind::MethodNotFound);
        assert_eq!(rpc.code(), Some(-32601));
        assert_eq!(rpc.raw_code(), Some(-32601));
    }

    #[test]
    fn classifies_standard_rpc_error_codes() {
        let cases = [
            (-32700, RpcErrorKind::Parse),
            (-32600, RpcErrorKind::InvalidRequest),
            (-32601, RpcErrorKind::MethodNotFound),
            (-32602, RpcErrorKind::InvalidParams),
            (-32603, RpcErrorKind::Internal),
            (-32042, RpcErrorKind::Server),
        ];
        for (code, expected) in cases {
            let transport = MockTransport::new().with_error("getNetwork", code, "failure");
            let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
            let rpc = client
                .get_network()
                .unwrap_err()
                .rpc_error()
                .cloned()
                .expect("typed rpc error");
            assert_eq!(rpc.kind(), expected, "code {code}");
            assert_eq!(rpc.code(), Some(code), "raw code {code}");
        }
    }

    #[test]
    fn preserves_unknown_provider_codes() {
        let transport = MockTransport::new().with_error("getNetwork", -77777, "custom");
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let rpc = client
            .get_network()
            .unwrap_err()
            .rpc_error()
            .cloned()
            .expect("typed rpc error");
        assert_eq!(rpc.kind(), RpcErrorKind::Unknown);
        assert_eq!(rpc.kind().as_str(), "unknown");
        assert_eq!(rpc.raw_code(), Some(-77777));
    }

    #[test]
    fn records_calls() {
        let transport = MockTransport::new().with_result("getNetwork", json!({}));
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        client.get_network().unwrap();
        assert_eq!(transport.calls(), vec!["getNetwork".to_string()]);
        let _ = &client;
    }

    #[test]
    fn builds_transport_from_json_fixture() {
        let fixture = json!({
            "getLatestLedger": { "sequence": 9 },
            "getNetwork": { "__error": { "code": -32000, "message": "boom" } }
        });
        let transport = MockTransport::from_json(&fixture).unwrap();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        assert_eq!(client.get_latest_ledger().unwrap().sequence, 9);
        assert!(client.get_network().is_err());
        assert!(MockTransport::from_json(&json!([])).is_err());
    }

    #[test]
    fn fixture_sequences_return_results_in_order() {
        let fixture = json!({
            "getLatestLedger": { "__sequence": [ { "sequence": 1 }, { "sequence": 2 } ] }
        });
        let transport = MockTransport::from_json(&fixture).unwrap();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        assert_eq!(client.get_latest_ledger().unwrap().sequence, 1);
        assert_eq!(client.get_latest_ledger().unwrap().sequence, 2);
    }

    #[test]
    fn endpoint_ports_use_scheme_defaults_and_overrides() {
        assert_eq!(Endpoint::parse("https://example.org").unwrap().port(), 443);
        assert_eq!(
            Endpoint::parse("https://example.org:8443").unwrap().port(),
            8443
        );
        assert_eq!(
            Endpoint::parse("http://localhost:8000").unwrap().port(),
            8000
        );
        assert_eq!(Endpoint::parse("http://localhost").unwrap().port(), 80);
        assert_eq!(Endpoint::parse("https://[::1]:9000").unwrap().port(), 9000);
    }

    #[test]
    fn endpoint_ssrf_policy_is_enforced() {
        let public = Endpoint::parse("https://8.8.8.8").unwrap();
        assert!(public.validate_ssrf(&SsrfPolicy::strict()).is_ok());

        let loopback = Endpoint::parse("http://127.0.0.1:8080").unwrap();
        assert!(loopback.validate_ssrf(&SsrfPolicy::strict()).is_err());
        assert!(loopback.validate_ssrf(&SsrfPolicy::local()).is_ok());

        let metadata = Endpoint::parse("https://169.254.169.254").unwrap();
        assert!(metadata.validate_ssrf(&SsrfPolicy::local()).is_err());
    }

    #[test]
    fn get_health_decodes_the_documented_fixture() {
        let fixture = json!({
            "getHealth": {
                "status": "healthy",
                "latestLedger": 3730763,
                "latestLedgerCloseTime": "1784671485",
                "oldestLedger": 3609804,
                "oldestLedgerCloseTime": "1784065656",
                "ledgerRetentionWindow": 120960
            }
        });
        let transport = MockTransport::from_json(&fixture).unwrap();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        let health = client.get_health().unwrap();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.latest_ledger, 3730763);
        assert_eq!(health.latest_ledger_close_time, "1784671485");
        assert_eq!(health.oldest_ledger, 3609804);
        assert_eq!(health.oldest_ledger_close_time, "1784065656");
        assert_eq!(health.ledger_retention_window, 120960);
        assert_eq!(transport.calls(), vec!["getHealth".to_string()]);
    }

    #[test]
    fn get_health_rejects_an_incomplete_result_instead_of_inventing_fields() {
        let fixture = json!({ "getHealth": { "status": "healthy", "latestLedger": 1 } });
        let transport = MockTransport::from_json(&fixture).unwrap();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let error = client.get_health().unwrap_err();
        assert!(matches!(error, ObservatoryError::Decode(_)), "{error:?}");
        assert!(error.to_string().contains("getHealth"), "{error}");
    }

    #[test]
    fn get_health_normalizes_rpc_errors() {
        let fixture = json!({
            "getHealth": { "__error": { "code": -32000, "message": "unavailable" } }
        });
        let transport = MockTransport::from_json(&fixture).unwrap();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let error = client.get_health().unwrap_err();
        assert!(matches!(error, ObservatoryError::Rpc(_)));
        assert!(error.to_string().contains("unavailable"), "{error}");
    }

    fn contract_id() -> String {
        format!("{}", stellar_strkey::Contract([9u8; 32]))
    }

    fn contract_data_entry() -> stellar_xdr::ContractDataEntry {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractId, Hash, ScAddress, ScVal,
        };
        ContractDataEntry {
            ext: stellar_xdr::ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash([9u8; 32]))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::Bool(true),
        }
    }

    #[test]
    fn get_contract_data_decodes_a_fixture() {
        use stellar_xdr::WriteXdr;
        let xdr = stellar_xdr::LedgerEntryData::ContractData(contract_data_entry())
            .to_xdr_base64(Limits::none())
            .unwrap();
        let fixture = json!({
            "getContractData": {
                "xdr": xdr,
                "lastModifiedLedgerSeq": 11,
                "liveUntilLedgerSeq": 22,
                "latestLedger": 33
            }
        });
        let client = RpcClient::new(
            Endpoint::parse("https://example.org").unwrap(),
            MockTransport::from_json(&fixture).unwrap(),
        );
        let request = GetContractDataRequest::new(
            contract_id(),
            ScVal::LedgerKeyContractInstance
                .to_xdr_base64(Limits::none())
                .unwrap(),
        );
        let result = client.get_contract_data(&request).unwrap();
        assert_eq!(result.last_modified_ledger_seq, Some(11));
        assert_eq!(result.live_until_ledger_seq, Some(22));
        assert_eq!(result.latest_ledger, Some(33));
        assert_eq!(result.xdr, xdr);
    }

    #[test]
    fn get_contract_data_builds_the_documented_request() {
        use stellar_xdr::WriteXdr;
        struct Capture(RefCell<Option<Value>>);
        impl Transport for Capture {
            fn send(&self, request: &Value) -> Result<Value> {
                *self.0.borrow_mut() = Some(request.clone());
                let xdr = stellar_xdr::LedgerEntryData::ContractData(contract_data_entry())
                    .to_xdr_base64(Limits::none())
                    .unwrap();
                Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": { "xdr": xdr } }))
            }
        }
        let transport = Capture(RefCell::new(None));
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        let key = ScVal::LedgerKeyContractInstance
            .to_xdr_base64(Limits::none())
            .unwrap();
        client
            .get_contract_data(
                &GetContractDataRequest::new(contract_id(), key.clone())
                    .with_durability(Durability::Temporary),
            )
            .unwrap();
        let request = transport.0.borrow().clone().expect("request captured");
        assert_eq!(request["method"], "getContractData");
        assert_eq!(request["params"]["contractId"], contract_id());
        assert_eq!(request["params"]["key"], key);
        assert_eq!(request["params"]["durability"], "temporary");
    }

    #[test]
    fn get_contract_data_normalizes_rpc_errors() {
        use stellar_xdr::WriteXdr;
        let fixture = json!({
            "getContractData": { "__error": { "code": -32000, "message": "entry not found" } }
        });
        let transport = MockTransport::from_json(&fixture).unwrap();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let key = ScVal::LedgerKeyContractInstance
            .to_xdr_base64(Limits::none())
            .unwrap();
        let request = GetContractDataRequest::new(contract_id(), key);
        let error = client.get_contract_data(&request).unwrap_err();
        assert!(matches!(error, ObservatoryError::Rpc(_)));
        assert!(error.to_string().contains("entry not found"), "{error}");
    }

    #[test]
    fn get_contract_data_rejects_invalid_input_before_calling() {
        use stellar_xdr::WriteXdr;
        let transport = MockTransport::new();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        let key = ScVal::LedgerKeyContractInstance
            .to_xdr_base64(Limits::none())
            .unwrap();

        let bad_key = GetContractDataRequest::new(contract_id(), "not-xdr");
        let error = client.get_contract_data(&bad_key).unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));

        let bad_contract = GetContractDataRequest::new("not-a-contract", key.clone());
        let error = client.get_contract_data(&bad_contract).unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));

        let empty_key = GetContractDataRequest::new(contract_id(), "");
        assert!(client.get_contract_data(&empty_key).is_err());
        assert!(transport.calls().is_empty());
    }

    #[test]
    fn get_contract_data_rejects_an_invalid_entry_response() {
        use stellar_xdr::WriteXdr;
        let fixture = json!({ "getContractData": { "xdr": "AAAA" } });
        let transport = MockTransport::from_json(&fixture).unwrap();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let key = ScVal::LedgerKeyContractInstance
            .to_xdr_base64(Limits::none())
            .unwrap();
        let request = GetContractDataRequest::new(contract_id(), key);
        let error = client.get_contract_data(&request).unwrap_err();
        assert!(matches!(error, ObservatoryError::Decode(_)));
    }

    #[test]
    fn rpc_timeouts_default_and_reject_zero() {
        let defaults = RpcTimeouts::default();
        assert_eq!(defaults.connect, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(defaults.read, DEFAULT_READ_TIMEOUT);
        assert!(RpcTimeouts::from_secs(1, 1).is_ok());
        assert!(RpcTimeouts::from_secs(0, 1).is_err());
        assert!(RpcTimeouts::from_secs(1, 0).is_err());
    }

    #[test]
    fn get_events_reads_cursor_and_bounds_the_page() {
        let transport = MockTransport::new().with_result(
            "getEvents",
            json!({
                "events": [],
                "cursor": "next-page",
                "latestLedger": 42,
                "oldestLedger": 7,
            }),
        );
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let page = client
            .get_events(json!({ "pagination": { "limit": 10 } }))
            .unwrap();
        assert_eq!(page.cursor.as_deref(), Some("next-page"));
        assert_eq!(page.latest_ledger, Some(42));
        assert_eq!(page.oldest_ledger, Some(7));
        assert!(page.events.is_empty());
    }

    #[test]
    fn get_events_rejects_a_missing_events_array() {
        let transport = MockTransport::new().with_result("getEvents", json!({ "cursor": "x" }));
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let error = client.get_events(json!({})).unwrap_err();
        assert!(matches!(error, ObservatoryError::Rpc(_)));
    }

    #[derive(Debug)]
    struct RecordingClock(std::cell::RefCell<Vec<Duration>>);

    impl RecordingClock {
        fn new() -> Self {
            RecordingClock(std::cell::RefCell::new(Vec::new()))
        }

        fn sleeps(&self) -> Vec<Duration> {
            self.0.borrow().clone()
        }
    }

    impl Clock for RecordingClock {
        fn sleep(&self, duration: Duration) {
            self.0.borrow_mut().push(duration);
        }
    }

    /// Fails with a transport error for the first N calls, then succeeds.
    #[derive(Debug)]
    struct FlakyTransport {
        remaining_failures: std::cell::Cell<usize>,
        calls: std::cell::Cell<usize>,
        error: fn() -> ObservatoryError,
    }

    impl FlakyTransport {
        fn new(failures: usize, error: fn() -> ObservatoryError) -> Self {
            FlakyTransport {
                remaining_failures: std::cell::Cell::new(failures),
                calls: std::cell::Cell::new(0),
                error,
            }
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl Transport for FlakyTransport {
        fn send(&self, _request: &Value) -> Result<Value> {
            self.calls.set(self.calls.get() + 1);
            if self.remaining_failures.get() > 0 {
                self.remaining_failures
                    .set(self.remaining_failures.get() - 1);
                return Err((self.error)());
            }
            Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": { "sequence": 7 } }))
        }
    }

    fn transport_failure() -> ObservatoryError {
        ObservatoryError::rpc("connection reset")
    }

    fn client_failure() -> ObservatoryError {
        ObservatoryError::from_rpc_error(RpcError::from_code(-32602, "invalid params"))
    }

    #[test]
    fn retry_policy_rejects_invalid_values() {
        assert!(RetryPolicy::new(0, Duration::from_millis(1), Duration::from_millis(2)).is_err());
        assert!(RetryPolicy::new(1, Duration::ZERO, Duration::from_millis(2)).is_err());
        assert!(RetryPolicy::new(1, Duration::from_millis(2), Duration::from_millis(1)).is_err());
        assert!(RetryPolicy::new(1, Duration::from_millis(1), Duration::from_millis(1)).is_ok());
        assert_eq!(
            RetryPolicy::default().max_attempts(),
            DEFAULT_MAX_RETRY_ATTEMPTS
        );
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let policy =
            RetryPolicy::new(10, Duration::from_millis(100), Duration::from_millis(350)).unwrap();
        assert_eq!(policy.delay_for(1), Duration::from_millis(100));
        assert_eq!(policy.delay_for(2), Duration::from_millis(200));
        assert_eq!(policy.delay_for(3), Duration::from_millis(350));
        assert_eq!(policy.delay_for(4), Duration::from_millis(350));
        assert_eq!(policy.delay_for(u32::MAX), Duration::from_millis(350));
    }

    #[test]
    fn retries_transient_failures_with_deterministic_backoff() {
        let transport = FlakyTransport::new(2, transport_failure);
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        let policy =
            RetryPolicy::new(3, Duration::from_millis(10), Duration::from_millis(15)).unwrap();
        let clock = RecordingClock::new();

        let result = client
            .call_with_retry("getLatestLedger", json!({}), &policy, &clock)
            .unwrap();

        assert_eq!(result["sequence"], 7);
        assert_eq!(transport.calls(), 3);
        assert_eq!(
            clock.sleeps(),
            vec![Duration::from_millis(10), Duration::from_millis(15)]
        );
    }

    #[test]
    fn client_errors_are_never_retried() {
        let transport = FlakyTransport::new(3, client_failure);
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        let clock = RecordingClock::new();

        let error = client
            .call_with_retry("getNetwork", json!({}), &RetryPolicy::default(), &clock)
            .unwrap_err();

        assert_eq!(transport.calls(), 1);
        assert!(clock.sleeps().is_empty());
        assert_eq!(
            error.rpc_error().map(RpcError::kind),
            Some(RpcErrorKind::InvalidParams)
        );
    }

    #[test]
    fn retries_are_bounded_by_max_attempts() {
        let transport = FlakyTransport::new(10, transport_failure);
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        let policy =
            RetryPolicy::new(3, Duration::from_millis(10), Duration::from_millis(20)).unwrap();
        let clock = RecordingClock::new();

        let error = client
            .call_with_retry("getNetwork", json!({}), &policy, &clock)
            .unwrap_err();

        assert!(matches!(error, ObservatoryError::Rpc(_)));
        assert_eq!(transport.calls(), 3);
        assert_eq!(
            clock.sleeps(),
            vec![Duration::from_millis(10), Duration::from_millis(20)]
        );
    }

    #[test]
    fn server_side_errors_are_retryable_but_parse_errors_are_not() {
        let server = ObservatoryError::from_rpc_error(RpcError::from_code(-32000, "unavailable"));
        let internal = ObservatoryError::from_rpc_error(RpcError::from_code(-32603, "busy"));
        let parse = ObservatoryError::from_rpc_error(RpcError::from_code(-32700, "bad json"));
        assert!(is_retryable(&server));
        assert!(is_retryable(&internal));
        assert!(!is_retryable(&parse));
        assert!(!is_retryable(&ObservatoryError::invalid("bad request")));
    }
}
