//! Signed webhook delivery with bounded retries.
//!
//! Delivery is transport-agnostic. [`deliver`] signs a payload with HMAC-SHA256
//! over `timestamp.body`, retries transient failures with exponential backoff,
//! and returns a typed record of every attempt. The default [`HttpTransport`]
//! handles loopback `http://` receivers for tests and local development; a
//! production deployment should plug in a TLS-capable [`WebhookTransport`] or a
//! TLS-terminating proxy.
//!
//! Tests inject both the clock and the sleeper, so they are offline and do not
//! wait for real backoff delays.

use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use observatory_core::{ObservatoryError, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Signature header carrying `sha256=<hex>`.
pub const SIGNATURE_HEADER: &str = "x-observatory-signature";
/// Timestamp header, in Unix seconds.
pub const TIMESTAMP_HEADER: &str = "x-observatory-timestamp";
/// Unique delivery id, stable across retries.
pub const DELIVERY_ID_HEADER: &str = "x-observatory-delivery-id";
/// Event name header.
pub const EVENT_HEADER: &str = "x-observatory-event";

/// Maximum accepted webhook payload size.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
/// Maximum accepted event name length.
pub const MAX_EVENT_BYTES: usize = 128;
/// Maximum accepted URL length.
pub const MAX_URL_BYTES: usize = 2048;

/// A webhook registration needed to deliver one event.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookRegistration {
    /// Stable registration id.
    pub id: String,
    /// Receiver URL. The built-in transport supports loopback `http://`.
    pub url: String,
    /// HMAC secret. Never logged or serialized.
    pub secret: String,
}

impl fmt::Debug for WebhookRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookRegistration")
            .field("id", &self.id)
            .field("url", &self.url)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Retry policy for one delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookConfig {
    /// Maximum number of attempts, including the first.
    pub max_attempts: u32,
    /// Delay before the second attempt.
    pub initial_backoff: Duration,
    /// Upper bound for any single backoff delay.
    pub max_backoff: Duration,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        WebhookConfig {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
        }
    }
}

impl WebhookConfig {
    /// Validates the retry policy.
    pub fn validate(&self) -> Result<()> {
        if !(1..=10).contains(&self.max_attempts) {
            return Err(ObservatoryError::invalid(
                "webhook max_attempts must be between 1 and 10",
            ));
        }
        if self.initial_backoff.is_zero() {
            return Err(ObservatoryError::invalid(
                "webhook initial_backoff must be greater than zero",
            ));
        }
        if self.max_backoff < self.initial_backoff {
            return Err(ObservatoryError::invalid(
                "webhook max_backoff must be at least initial_backoff",
            ));
        }
        if self.timeout.is_zero() {
            return Err(ObservatoryError::invalid(
                "webhook timeout must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Final state of a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    /// The receiver returned a 2xx response.
    Delivered,
    /// The attempt budget or a non-retryable response ended delivery.
    Failed,
}

/// One delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryAttempt {
    /// 1-based attempt number.
    pub attempt: u32,
    /// Timestamp used for the signature, in Unix seconds.
    pub at_secs: u64,
    /// HTTP status, when a response was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Transport error, when no response was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// When the next attempt is scheduled, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at_secs: Option<u64>,
}

/// The full, bounded record of one delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryOutcome {
    /// Unique delivery id, stable across retries.
    pub delivery_id: String,
    /// Registration id.
    pub webhook_id: String,
    /// Event name.
    pub event: String,
    /// Final status.
    pub status: DeliveryStatus,
    /// Every attempt, in order.
    pub attempts: Vec<DeliveryAttempt>,
    /// Last HTTP status received, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_status: Option<u16>,
    /// Last transport error, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// A transport that performs one HTTP POST.
pub trait WebhookTransport {
    /// POST `body` to `url` with `headers`, returning the HTTP status.
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        timeout: Duration,
    ) -> std::result::Result<u16, String>;
}

/// Source of wall-clock time, injected so tests are deterministic.
pub trait Clock {
    /// Current Unix time in seconds.
    fn now_secs(&self) -> u64;
}

/// Real system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }
}

/// Injected delay, so tests never wait for real backoff.
pub trait Sleeper {
    /// Sleep for `duration`.
    fn sleep(&self, duration: Duration);
}

/// Real thread sleep.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Computes HMAC-SHA256.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        normalized[..32].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    let digest = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

/// Signs `timestamp.body` and returns lowercase hex.
pub fn sign(secret: &str, timestamp: u64, body: &[u8]) -> String {
    let mut message = format!("{timestamp}.").into_bytes();
    message.extend_from_slice(body);
    hex::encode(hmac_sha256(secret.as_bytes(), &message))
}

/// Verifies a signature in constant time.
///
/// `signature` may be raw hex or `sha256=<hex>`.
#[must_use]
pub fn verify(secret: &str, timestamp: u64, body: &[u8], signature: &str) -> bool {
    let signature = signature
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or(signature.trim());
    let Ok(provided) = hex::decode(signature) else {
        return false;
    };
    let expected = sign(secret, timestamp, body).into_bytes();
    let Ok(expected) = hex::decode(expected) else {
        return false;
    };
    constant_time_eq(&provided, &expected)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Delivers one signed event with bounded exponential backoff.
pub fn deliver<T, C, S>(
    registration: &WebhookRegistration,
    event: &str,
    payload: &[u8],
    config: &WebhookConfig,
    transport: &T,
    clock: &C,
    sleeper: &S,
) -> Result<DeliveryOutcome>
where
    T: WebhookTransport,
    C: Clock,
    S: Sleeper,
{
    if registration.id.trim().is_empty() {
        return Err(ObservatoryError::invalid("webhook id must not be empty"));
    }
    if registration.secret.is_empty() {
        return Err(ObservatoryError::invalid(
            "webhook secret must not be empty",
        ));
    }
    if registration.url.is_empty() || registration.url.len() > MAX_URL_BYTES {
        return Err(ObservatoryError::invalid(
            "webhook url is empty or too long",
        ));
    }
    if event.trim().is_empty() || event.len() > MAX_EVENT_BYTES {
        return Err(ObservatoryError::invalid(
            "webhook event must be non-empty and within the length limit",
        ));
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ObservatoryError::invalid(format!(
            "webhook payload is {} bytes; limit is {MAX_PAYLOAD_BYTES}",
            payload.len()
        )));
    }
    config.validate()?;

    let delivery_id = new_delivery_id()?;
    let mut attempts = Vec::new();
    let mut last_status = None;
    let mut last_error = None;

    for attempt in 1..=config.max_attempts {
        let timestamp = clock.now_secs();
        let signature = sign(&registration.secret, timestamp, payload);
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (DELIVERY_ID_HEADER.to_string(), delivery_id.clone()),
            (EVENT_HEADER.to_string(), event.to_string()),
            (TIMESTAMP_HEADER.to_string(), timestamp.to_string()),
            (SIGNATURE_HEADER.to_string(), format!("sha256={signature}")),
        ];

        let outcome = transport.post(&registration.url, &headers, payload, config.timeout);
        let (status, error) = match outcome {
            Ok(status) => (Some(status), None),
            Err(error) => (None, Some(error)),
        };
        last_status = status.or(last_status);
        last_error = error.clone().or(last_error);

        let retryable = match status {
            Some(status) => status == 408 || status == 429 || (500..600).contains(&status),
            None => true,
        };
        let delivered = status.is_some_and(|status| (200..300).contains(&status));
        if delivered || !retryable || attempt == config.max_attempts {
            attempts.push(DeliveryAttempt {
                attempt,
                at_secs: timestamp,
                status,
                error,
                next_retry_at_secs: None,
            });
            return Ok(DeliveryOutcome {
                delivery_id,
                webhook_id: registration.id.clone(),
                event: event.to_string(),
                status: if delivered {
                    DeliveryStatus::Delivered
                } else {
                    DeliveryStatus::Failed
                },
                attempts,
                last_status,
                last_error,
            });
        }

        let backoff = backoff_for(config, attempt);
        let next_retry_at = timestamp.saturating_add(backoff.as_secs().max(1));
        attempts.push(DeliveryAttempt {
            attempt,
            at_secs: timestamp,
            status,
            error,
            next_retry_at_secs: Some(next_retry_at),
        });
        sleeper.sleep(backoff);
    }

    // `max_attempts` is at least one, so the loop always returns. This keeps the
    // compiler satisfied without an unreachable panic.
    Ok(DeliveryOutcome {
        delivery_id,
        webhook_id: registration.id.clone(),
        event: event.to_string(),
        status: DeliveryStatus::Failed,
        attempts,
        last_status,
        last_error,
    })
}

fn backoff_for(config: &WebhookConfig, attempt: u32) -> Duration {
    let factor = 1u32 << attempt.saturating_sub(1).min(20);
    let millis = config
        .initial_backoff
        .as_millis()
        .saturating_mul(u128::from(factor))
        .min(config.max_backoff.as_millis());
    Duration::from_millis(millis as u64)
}

fn new_delivery_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| ObservatoryError::internal(format!("randomness failure: {error}")))?;
    Ok(format!("whd_{}", hex::encode(bytes)))
}

/// A built-in HTTP transport for loopback receivers.
///
/// Only `http://` is supported. By default only loopback hosts are allowed; call
/// [`HttpTransport::allow_insecure_http`] for explicitly trusted non-loopback
/// plaintext endpoints. HTTPS requires a TLS-capable custom transport or a
/// TLS-terminating proxy.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpTransport {
    allow_insecure_http: bool,
}

impl HttpTransport {
    /// Create a loopback-only transport.
    #[must_use]
    pub fn new() -> Self {
        HttpTransport {
            allow_insecure_http: false,
        }
    }

    /// Allow plaintext HTTP to non-loopback hosts.
    #[must_use]
    pub fn allow_insecure_http(mut self) -> Self {
        self.allow_insecure_http = true;
        self
    }
}

impl WebhookTransport for HttpTransport {
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        timeout: Duration,
    ) -> std::result::Result<u16, String> {
        let (authority, path) = parse_http_url(url)?;
        let (host, port) = split_authority(&authority)?;
        if !self.allow_insecure_http && !is_loopback(&host) {
            return Err(format!(
                "plaintext webhook delivery to `{host}` is disabled; \
                 use a TLS-capable transport or a TLS-terminating proxy"
            ));
        }

        let mut stream = TcpStream::connect((host.as_str(), port))
            .map_err(|error| format!("cannot connect to webhook receiver: {error}"))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| format!("cannot set webhook read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| format!("cannot set webhook write timeout: {error}"))?;

        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            let forbidden = |text: &str| text.contains('\r') || text.contains('\n');
            if forbidden(name) || forbidden(value) {
                return Err("webhook header contains a forbidden newline".to_string());
            }
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");

        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(body))
            .and_then(|()| stream.flush())
            .map_err(|error| format!("cannot write webhook request: {error}"))?;

        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|error| format!("cannot read webhook response: {error}"))?;
        parse_status(&status_line).ok_or_else(|| "invalid webhook response status line".to_string())
    }
}

fn parse_http_url(url: &str) -> std::result::Result<(String, String), String> {
    if url.len() > MAX_URL_BYTES {
        return Err("webhook url is too long".to_string());
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("webhook url contains whitespace or control characters".to_string());
    }
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        "the built-in webhook transport supports http:// only; \
         use a TLS-capable transport for https"
            .to_string()
    })?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err("webhook url has an invalid authority".to_string());
    }
    Ok((authority.to_string(), path))
}

fn split_authority(authority: &str) -> std::result::Result<(String, u16), String> {
    if authority.starts_with('[') {
        return Err("IPv6 webhook hosts are not supported by the built-in transport".to_string());
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .map_err(|_| "webhook url has an invalid port".to_string())?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), 80)),
    }
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn parse_status(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;

    #[derive(Debug)]
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now_secs(&self) -> u64 {
            self.0
        }
    }

    #[derive(Debug, Default)]
    struct RecordingSleeper {
        delays: Mutex<Vec<Duration>>,
    }

    impl Sleeper for RecordingSleeper {
        fn sleep(&self, duration: Duration) {
            self.delays.lock().unwrap().push(duration);
        }
    }

    #[derive(Debug, Clone)]
    struct Captured {
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    }

    fn spawn_receiver(statuses: Vec<u16>) -> (String, thread::JoinHandle<Vec<Captured>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/webhook");
        let handle = thread::spawn(move || {
            let mut captured = Vec::new();
            for status in statuses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut content_length = 0usize;
                let mut headers = BTreeMap::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let line = line.trim_end();
                    if line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        let name = name.to_ascii_lowercase();
                        let value = value.trim();
                        if name == "content-length" {
                            content_length = value.parse().unwrap();
                        }
                        headers.insert(name, value.to_string());
                    }
                }
                let mut body = vec![0u8; content_length];
                reader.read_exact(&mut body).unwrap();
                captured.push(Captured { headers, body });
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            captured
        });
        (url, handle)
    }

    #[test]
    fn hmac_matches_the_rfc_4231_vector() {
        let digest = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex::encode(digest),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn signatures_verify_and_detect_tampering() {
        let secret = "top-secret";
        let signature = sign(secret, 1_700_000_000, b"{\"ok\":true}");
        assert!(verify(secret, 1_700_000_000, b"{\"ok\":true}", &signature));
        assert!(verify(
            secret,
            1_700_000_000,
            b"{\"ok\":true}",
            &format!("sha256={signature}")
        ));
        assert!(!verify(
            secret,
            1_700_000_000,
            b"{\"ok\":false}",
            &signature
        ));
        assert!(!verify(secret, 1_700_000_001, b"{\"ok\":true}", &signature));
        assert!(!verify(
            "wrong",
            1_700_000_000,
            b"{\"ok\":true}",
            &signature
        ));
        assert!(!verify(secret, 1_700_000_000, b"{\"ok\":true}", "not-hex"));
    }

    #[test]
    fn delivery_retries_transient_failures_with_bounded_backoff() {
        let (url, receiver) = spawn_receiver(vec![500, 500, 200]);
        let registration = WebhookRegistration {
            id: "wh_1".to_string(),
            url,
            secret: "secret".to_string(),
        };
        let config = WebhookConfig {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(100),
            timeout: Duration::from_secs(2),
        };
        let sleeper = RecordingSleeper::default();
        let outcome = deliver(
            &registration,
            "scan.completed",
            b"{\"scan\":1}",
            &config,
            &HttpTransport::new(),
            &FixedClock(1_700_000_000),
            &sleeper,
        )
        .unwrap();

        assert_eq!(outcome.status, DeliveryStatus::Delivered);
        assert_eq!(outcome.attempts.len(), 3);
        assert_eq!(outcome.attempts[0].status, Some(500));
        assert!(outcome.attempts[0].next_retry_at_secs.is_some());
        assert_eq!(
            *sleeper.delays.lock().unwrap(),
            vec![Duration::from_millis(10), Duration::from_millis(20)]
        );

        let captured = receiver.join().unwrap();
        assert_eq!(captured.len(), 3);
        let delivery_ids: Vec<&str> = captured
            .iter()
            .map(|request| request.headers.get(DELIVERY_ID_HEADER).unwrap().as_str())
            .collect();
        assert!(delivery_ids.iter().all(|id| *id == delivery_ids[0]));
        for request in &captured {
            let timestamp: u64 = request
                .headers
                .get(TIMESTAMP_HEADER)
                .unwrap()
                .parse()
                .unwrap();
            let signature = request.headers.get(SIGNATURE_HEADER).unwrap();
            assert!(verify("secret", timestamp, &request.body, signature));
        }
    }

    #[test]
    fn delivery_stops_at_the_attempt_limit() {
        let (url, receiver) = spawn_receiver(vec![503, 503]);
        let registration = WebhookRegistration {
            id: "wh_2".to_string(),
            url,
            secret: "secret".to_string(),
        };
        let config = WebhookConfig {
            max_attempts: 2,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
            timeout: Duration::from_secs(2),
        };
        let outcome = deliver(
            &registration,
            "scan.failed",
            b"{}",
            &config,
            &HttpTransport::new(),
            &FixedClock(1_700_000_000),
            &RecordingSleeper::default(),
        )
        .unwrap();
        assert_eq!(outcome.status, DeliveryStatus::Failed);
        assert_eq!(outcome.attempts.len(), 2);
        assert_eq!(outcome.last_status, Some(503));
        receiver.join().unwrap();
    }

    #[test]
    fn non_retryable_responses_fail_immediately() {
        let (url, receiver) = spawn_receiver(vec![400]);
        let registration = WebhookRegistration {
            id: "wh_3".to_string(),
            url,
            secret: "secret".to_string(),
        };
        let outcome = deliver(
            &registration,
            "scan.completed",
            b"{}",
            &WebhookConfig::default(),
            &HttpTransport::new(),
            &FixedClock(1_700_000_000),
            &RecordingSleeper::default(),
        )
        .unwrap();
        assert_eq!(outcome.status, DeliveryStatus::Failed);
        assert_eq!(outcome.attempts.len(), 1);
        assert_eq!(outcome.last_status, Some(400));
        receiver.join().unwrap();
    }

    #[test]
    fn transport_rejects_plaintext_non_loopback_and_https() {
        let transport = HttpTransport::new();
        let error = transport
            .post(
                "http://example.com/hook",
                &[],
                b"{}",
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert!(error.contains("TLS"));
        let error = transport
            .post(
                "https://example.com/hook",
                &[],
                b"{}",
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert!(error.contains("TLS"));
    }

    #[test]
    fn delivery_ids_are_unique() {
        let first = new_delivery_id().unwrap();
        let second = new_delivery_id().unwrap();
        assert_ne!(first, second);
        assert!(first.starts_with("whd_"));
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let registration = WebhookRegistration {
            id: "wh".to_string(),
            url: "http://127.0.0.1/".to_string(),
            secret: "super-secret".to_string(),
        };
        let rendered = format!("{registration:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn payload_and_event_limits_are_enforced() {
        let registration = WebhookRegistration {
            id: "wh".to_string(),
            url: "http://127.0.0.1:1/".to_string(),
            secret: "secret".to_string(),
        };
        let clock = FixedClock(1);
        let sleeper = RecordingSleeper::default();
        let too_large = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        assert!(deliver(
            &registration,
            "event",
            &too_large,
            &WebhookConfig::default(),
            &HttpTransport::new(),
            &clock,
            &sleeper
        )
        .is_err());
        let long_event = "x".repeat(MAX_EVENT_BYTES + 1);
        assert!(deliver(
            &registration,
            &long_event,
            b"{}",
            &WebhookConfig::default(),
            &HttpTransport::new(),
            &clock,
            &sleeper
        )
        .is_err());
    }

    #[test]
    fn elapsed_retry_timestamps_advance() {
        let (url, receiver) = spawn_receiver(vec![500, 200]);
        let registration = WebhookRegistration {
            id: "wh".to_string(),
            url,
            secret: "secret".to_string(),
        };
        let config = WebhookConfig {
            max_attempts: 2,
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
        };
        let sleeper = RecordingSleeper::default();
        let outcome = deliver(
            &registration,
            "event",
            b"{}",
            &config,
            &HttpTransport::new(),
            &FixedClock(100),
            &sleeper,
        )
        .unwrap();
        assert_eq!(outcome.attempts[0].next_retry_at_secs, Some(105));
        receiver.join().unwrap();
    }
}
