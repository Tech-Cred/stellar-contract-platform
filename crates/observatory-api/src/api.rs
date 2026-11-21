//! Versioned REST router with authentication, authorization, and rate limiting.
//!
//! The router is transport-agnostic: [`Api::handle`] takes a parsed [`Request`]
//! and returns a [`Response`]. The HTTP adapter in `crate::http` is a thin
//! wrapper, so the routing logic is fully unit-testable without sockets.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use observatory_core::{ObservatoryError, Result as CoreResult, SCHEMA_VERSION, TOOL_NAME};
use observatory_output::report;
use observatory_platform::{
    authorize, ApiKeyStore, AuditEvent, AuditLog, CompatibilityPolicy, JobQueue, Observatory,
    Permission, PlatformConfig, Principal, RateLimiter, Role, WebhookEvent, WebhookStore,
};
use serde::Serialize;
use serde_json::Value;

use crate::dto::{
    decode_wasm, CancelJobRequest, CompatibilityRequest, CreateJobRequest, CreateWebhookRequest,
    DiffRequest, EventsRequest, InspectRequest, UpdateWebhookRequest, WasmRequest,
};
use crate::http::{Request, Response};
use crate::metrics::{self, Metrics};

/// The API version prefix.
pub const API_PREFIX: &str = "/api/v1";

/// The Prometheus metrics endpoint path.
pub const METRICS_PATH: &str = "/api/v1/metrics";

/// The declared routes: `(method, path)`. Used by the router and by the
/// OpenAPI synchronization test.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/readiness"),
    ("GET", "/api/v1/version"),
    ("GET", METRICS_PATH),
    ("POST", "/api/v1/contracts/inspect"),
    ("POST", "/api/v1/contracts/spec"),
    ("POST", "/api/v1/contracts/diff"),
    ("POST", "/api/v1/contracts/compatibility"),
    ("POST", "/api/v1/contracts/fingerprint"),
    ("POST", "/api/v1/contracts/security"),
    ("POST", "/api/v1/contracts/events"),
    ("POST", "/api/v1/jobs"),
    ("GET", "/api/v1/jobs"),
    ("POST", "/api/v1/jobs/cancel"),
    ("GET", "/api/v1/audit/events"),
    ("POST", "/api/v1/webhooks"),
    ("GET", "/api/v1/webhooks"),
    ("GET", "/api/v1/webhooks/{id}"),
    ("PATCH", "/api/v1/webhooks/{id}"),
    ("DELETE", "/api/v1/webhooks/{id}"),
];

/// Maximum number of events returned by one `/contracts/events` request.
pub const MAX_EVENT_RESULTS: usize = 1000;

/// An API error with an HTTP status and a stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// HTTP status code.
    pub status: u16,
    /// Stable machine-readable code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
}

impl ApiError {
    fn new(status: u16, code: &str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code: code.to_string(),
            message: message.into(),
        }
    }

    fn unauthorized() -> Self {
        ApiError::new(401, "unauthorized", "a valid API key is required")
    }

    fn forbidden() -> Self {
        ApiError::new(
            403,
            "forbidden",
            "the API key lacks the required permission",
        )
    }

    fn bad_request(message: impl Into<String>) -> Self {
        ApiError::new(400, "bad_request", message)
    }
}

impl From<ObservatoryError> for ApiError {
    fn from(error: ObservatoryError) -> Self {
        let status = match error {
            ObservatoryError::InvalidInput(_) => 400,
            ObservatoryError::Decode(_) | ObservatoryError::Wasm(_) | ObservatoryError::Spec(_) => {
                400
            }
            ObservatoryError::Unsupported(_) => 422,
            ObservatoryError::Rpc(_) => 502,
            ObservatoryError::Verification(_) => 422,
            ObservatoryError::Io(_) | ObservatoryError::Internal(_) => 500,
        };
        ApiError {
            status,
            code: error.code().as_str().to_string(),
            message: error.to_string(),
        }
    }
}

/// The API application.
pub struct Api {
    observatory: Observatory,
    keys: RwLock<ApiKeyStore>,
    audit: RwLock<AuditLog>,
    jobs: RwLock<JobQueue>,
    webhooks: RwLock<WebhookStore>,
    limiter: RateLimiter,
    config: PlatformConfig,
    counter: AtomicU64,
    metrics: Metrics,
}

impl Api {
    /// Create an API with the given configuration and no keys.
    #[must_use]
    pub fn new(config: PlatformConfig) -> Self {
        let limiter = RateLimiter::new(config.rate_limit);
        Api {
            observatory: Observatory::new(),
            keys: RwLock::new(ApiKeyStore::new()),
            audit: RwLock::new(AuditLog::default()),
            jobs: RwLock::new(JobQueue::new(2)),
            webhooks: RwLock::new(WebhookStore::new()),
            limiter,
            config,
            counter: AtomicU64::new(0),
            metrics: Metrics::new(),
        }
    }

    /// Retained audit events, oldest first.
    #[must_use]
    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.audit.read().expect("audit log poisoned").snapshot()
    }

    fn record_audit(
        &self,
        actor: Option<String>,
        action: &str,
        resource: &str,
        outcome: &str,
        request_id: Option<String>,
        timestamp: u64,
    ) {
        self.audit
            .write()
            .expect("audit log poisoned")
            .record(AuditEvent::new(
                timestamp, actor, action, resource, outcome, request_id,
            ));
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> &PlatformConfig {
        &self.config
    }

    /// Generate a key and return its plaintext exactly once.
    pub fn generate_key(&self, role: Role, label: &str) -> CoreResult<String> {
        let (plaintext, record) = {
            let mut keys = self.keys.write().expect("key store poisoned");
            keys.generate(role, label)?
        };
        self.record_audit(
            None,
            "key.create",
            &format!("key:{}", record.id),
            "success",
            None,
            0,
        );
        Ok(plaintext)
    }

    /// Insert a pre-hashed key (fixtures/imports).
    pub fn insert_hashed_key(
        &self,
        id: impl Into<String>,
        hash: impl Into<String>,
        role: Role,
        label: &str,
    ) {
        let mut keys = self.keys.write().expect("key store poisoned");
        keys.insert_hashed(id, hash, role, label);
    }

    /// Register a key from its plaintext form (`sco_<id>_<secret>`).
    pub fn insert_plaintext_key(&self, plaintext: &str, role: Role, label: &str) -> CoreResult<()> {
        let mut keys = self.keys.write().expect("key store poisoned");
        keys.insert_plaintext(plaintext, role, label)?;
        Ok(())
    }

    /// Revoke a key.
    pub fn revoke_key(&self, id: &str) -> bool {
        let revoked = {
            let mut keys = self.keys.write().expect("key store poisoned");
            keys.revoke(id)
        };
        self.record_audit(
            None,
            "key.revoke",
            &format!("key:{id}"),
            if revoked { "success" } else { "failure" },
            None,
            0,
        );
        revoked
    }

    /// Change a live key's role.
    pub fn change_role(&self, id: &str, role: Role) -> bool {
        let changed = {
            let mut keys = self.keys.write().expect("key store poisoned");
            keys.set_role(id, role)
        };
        self.record_audit(
            None,
            "key.role_change",
            &format!("key:{id}:{}", role.name()),
            if changed { "success" } else { "failure" },
            None,
            0,
        );
        changed
    }

    /// Handle a request.
    #[must_use]
    pub fn handle(&self, request: &Request, client_id: &str, now_secs: u64) -> Response {
        let request_id = format!(
            "req-{:016x}",
            self.counter.fetch_add(1, Ordering::Relaxed) + 1
        );
        self.metrics.record_request();
        let principal = self.principal(request);
        let rate_key = principal
            .as_ref()
            .map(|principal| principal.key_id.clone())
            .unwrap_or_else(|| format!("client:{client_id}"));
        let decision = self.limiter.check(&rate_key, now_secs);
        let actor = principal.as_ref().map(|principal| principal.key_id.clone());

        if !decision.allowed {
            self.record_audit(
                actor.clone(),
                "request.rate_limited",
                &request.path,
                "denied",
                Some(request_id.clone()),
                now_secs,
            );
        }

        let mut response = if !decision.allowed {
            error_response(429, "rate_limited", "rate limit exceeded")
        } else if request.method == "OPTIONS" {
            self.preflight(request)
        } else {
            match self.route(request, principal.as_ref(), now_secs, &request_id) {
                Ok(response) => response,
                Err(error) => error_response(error.status, &error.code, &error.message),
            }
        };
        if decision.allowed {
            let outcome = if response.status < 400 {
                "success"
            } else {
                "failure"
            };
            match response.status {
                401 => self.record_audit(
                    None,
                    "auth.failure",
                    &request.path,
                    "denied",
                    Some(request_id.clone()),
                    now_secs,
                ),
                403 => self.record_audit(
                    actor.clone(),
                    "auth.forbidden",
                    &request.path,
                    "denied",
                    Some(request_id.clone()),
                    now_secs,
                ),
                _ if request.method == "POST" && request.path.starts_with("/api/v1/contracts/") => {
                    self.record_audit(
                        actor.clone(),
                        "analysis.run",
                        &request.path,
                        outcome,
                        Some(request_id.clone()),
                        now_secs,
                    );
                }
                _ => {}
            }
        }
        let analysis = response.status == 200
            && request.method == "POST"
            && request.path.starts_with("/api/v1/contracts/");
        self.metrics.record_outcome(response.status, analysis);
        response
            .headers
            .push(("X-Request-Id".to_string(), request_id));
        response
            .headers
            .push(("X-RateLimit-Limit".to_string(), decision.limit.to_string()));
        response.headers.push((
            "X-RateLimit-Remaining".to_string(),
            decision.remaining.to_string(),
        ));
        response.headers.push((
            "X-RateLimit-Reset".to_string(),
            decision.reset_after_secs.to_string(),
        ));
        response.headers.extend(self.cors_headers(request));
        response
    }

    fn preflight(&self, request: &Request) -> Response {
        let Some(origin) = request.header("origin") else {
            return error_response(400, "bad_request", "preflight requires an Origin header");
        };
        if !self.config.cors.is_allowed_origin(origin) {
            return error_response(403, "cors_origin_denied", "origin is not allowed");
        }
        Response::empty(204)
    }

    fn cors_headers(&self, request: &Request) -> Vec<(String, String)> {
        let Some(origin) = request.header("origin") else {
            return Vec::new();
        };
        if !self.config.cors.is_allowed_origin(origin) {
            return Vec::new();
        }
        let mut headers = vec![
            (
                "Access-Control-Allow-Origin".to_string(),
                origin.to_string(),
            ),
            ("Vary".to_string(), "Origin".to_string()),
        ];
        if request.method == "OPTIONS" {
            headers.push((
                "Access-Control-Allow-Methods".to_string(),
                self.config.cors.methods().join(", "),
            ));
            headers.push((
                "Access-Control-Allow-Headers".to_string(),
                self.config.cors.headers().join(", "),
            ));
            headers.push(("Access-Control-Max-Age".to_string(), "600".to_string()));
        }
        headers
    }

    fn principal(&self, request: &Request) -> Option<Principal> {
        let provided = request
            .header("x-api-key")
            .map(str::to_string)
            .or_else(|| {
                request
                    .header("authorization")
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .map(str::to_string)
            })?;
        let keys = self.keys.read().expect("key store poisoned");
        keys.authenticate(&provided)
    }

    fn require(
        &self,
        principal: Option<&Principal>,
        permission: Permission,
    ) -> Result<(), ApiError> {
        if !self.config.require_auth {
            return Ok(());
        }
        let principal = principal.ok_or_else(ApiError::unauthorized)?;
        if authorize(principal.role, permission) {
            Ok(())
        } else {
            Err(ApiError::forbidden())
        }
    }

    fn route(
        &self,
        request: &Request,
        principal: Option<&Principal>,
        now_secs: u64,
        request_id: &str,
    ) -> Result<Response, ApiError> {
        let actor = principal.map(|principal| principal.key_id.clone());
        if request.path == "/api/v1/webhooks" {
            return self.route_webhooks(request, principal);
        }
        if let Some(id) = request.path.strip_prefix("/api/v1/webhooks/") {
            return self.route_webhook_item(request, principal, id);
        }
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/api/v1/health") => Ok(response(
                200,
                "health",
                &serde_json::json!({ "status": "ok" }),
            )),
            ("GET", "/api/v1/readiness") => Ok(response(
                200,
                "readiness",
                &serde_json::json!({
                    "status": "ready",
                    "auth_required": self.config.require_auth,
                }),
            )),
            ("GET", "/api/v1/version") => Ok(response(
                200,
                "version",
                &serde_json::json!({
                    "tool": TOOL_NAME,
                    "version": env!("CARGO_PKG_VERSION"),
                    "schema_version": SCHEMA_VERSION,
                    "api_version": "v1",
                }),
            )),
            ("GET", "/api/v1/metrics") => {
                let snapshot = self.metrics.snapshot();
                if wants_json(request) {
                    Ok(response(200, "metrics", &snapshot))
                } else {
                    Ok(Response::text(
                        200,
                        metrics::CONTENT_TYPE,
                        snapshot.to_prometheus(),
                    ))
                }
            }
            ("POST", "/api/v1/contracts/inspect") => {
                self.require(principal, Permission::RunAnalysis)?;
                let body: InspectRequest = parse_json(request)?;
                let wasm = decode_wasm(&body.wasm_base64).map_err(ApiError::from)?;
                let outcome = self
                    .observatory
                    .inspect(&wasm, body.security)
                    .map_err(ApiError::from)?;
                Ok(response(200, "inspect", &outcome))
            }
            ("POST", "/api/v1/contracts/spec") => {
                self.require(principal, Permission::RunAnalysis)?;
                let body: WasmRequest = parse_json(request)?;
                let wasm = decode_wasm(&body.wasm_base64).map_err(ApiError::from)?;
                let outcome = self.observatory.spec(&wasm).map_err(ApiError::from)?;
                Ok(response(200, "spec", &outcome))
            }
            ("POST", "/api/v1/contracts/diff") => {
                self.require(principal, Permission::RunAnalysis)?;
                let body: DiffRequest = parse_json(request)?;
                let old = decode_wasm(&body.old_wasm_base64).map_err(ApiError::from)?;
                let new = decode_wasm(&body.new_wasm_base64).map_err(ApiError::from)?;
                let outcome = self.observatory.diff(&old, &new).map_err(ApiError::from)?;
                Ok(response(200, "diff", &outcome))
            }
            ("POST", "/api/v1/contracts/compatibility") => {
                self.require(principal, Permission::RunAnalysis)?;
                let body: CompatibilityRequest = parse_json(request)?;
                let policy = match body.policy.as_str() {
                    "strict" => CompatibilityPolicy::strict(),
                    "lenient" => CompatibilityPolicy::lenient(),
                    other => {
                        return Err(ApiError::bad_request(format!(
                            "unknown policy `{other}`; expected strict or lenient"
                        )))
                    }
                };
                let old = decode_wasm(&body.old_wasm_base64).map_err(ApiError::from)?;
                let new = decode_wasm(&body.new_wasm_base64).map_err(ApiError::from)?;
                let outcome = self
                    .observatory
                    .compatibility(&old, &new, policy)
                    .map_err(ApiError::from)?;
                Ok(response(200, "compat", &outcome))
            }
            ("POST", "/api/v1/contracts/fingerprint") => {
                self.require(principal, Permission::RunAnalysis)?;
                let body: WasmRequest = parse_json(request)?;
                let wasm = decode_wasm(&body.wasm_base64).map_err(ApiError::from)?;
                let outcome = self
                    .observatory
                    .fingerprint(&wasm)
                    .map_err(ApiError::from)?;
                Ok(response(200, "fingerprint", &outcome))
            }
            ("POST", "/api/v1/contracts/security") => {
                self.require(principal, Permission::RunAnalysis)?;
                let body: WasmRequest = parse_json(request)?;
                let wasm = decode_wasm(&body.wasm_base64).map_err(ApiError::from)?;
                let outcome = self.observatory.security(&wasm).map_err(ApiError::from)?;
                Ok(response(200, "security", &outcome))
            }
            ("POST", "/api/v1/contracts/events") => {
                self.require(principal, Permission::RunAnalysis)?;
                let body: EventsRequest = parse_json(request)?;
                let limit = body.limit.unwrap_or(100);
                if limit == 0 || limit > MAX_EVENT_RESULTS {
                    return Err(ApiError::bad_request(format!(
                        "limit must be between 1 and {MAX_EVENT_RESULTS}"
                    )));
                }
                let events = self
                    .observatory
                    .events_filtered(
                        &body.fixture,
                        body.contract.as_deref(),
                        body.topic.as_deref(),
                        body.event_type.as_deref(),
                        Some(limit),
                    )
                    .map_err(ApiError::from)?;
                Ok(response(200, "events", &events))
            }
            ("POST", "/api/v1/jobs") => {
                self.require(principal, Permission::RunAnalysis)?;
                let body: CreateJobRequest = parse_json(request)?;
                let job = self
                    .jobs
                    .write()
                    .expect("job queue poisoned")
                    .enqueue(
                        &body.kind,
                        body.idempotency_key.as_deref(),
                        body.max_attempts,
                        now_secs,
                    )
                    .map_err(ApiError::from)?;
                self.record_audit(
                    actor.clone(),
                    "job.create",
                    &format!("job:{}", job.id),
                    "success",
                    Some(request_id.to_string()),
                    now_secs,
                );
                Ok(response(201, "job", &job))
            }
            ("GET", "/api/v1/jobs") => {
                self.require(principal, Permission::RunAnalysis)?;
                let queue = self.jobs.read().expect("job queue poisoned");
                if let Some(id) = query_value(request, "id") {
                    match queue.job(id) {
                        Some(job) => Ok(response(200, "job", job)),
                        None => Err(ApiError::new(404, "not_found", "unknown job")),
                    }
                } else {
                    Ok(response(200, "jobs", &queue.jobs()))
                }
            }
            ("POST", "/api/v1/jobs/cancel") => {
                self.require(principal, Permission::RunAnalysis)?;
                let body: CancelJobRequest = parse_json(request)?;
                let cancelled = self
                    .jobs
                    .write()
                    .expect("job queue poisoned")
                    .cancel(&body.id, now_secs);
                if !cancelled {
                    return Err(ApiError::bad_request("job is not queued or does not exist"));
                }
                self.record_audit(
                    actor.clone(),
                    "job.cancel",
                    &format!("job:{}", body.id),
                    "success",
                    Some(request_id.to_string()),
                    now_secs,
                );
                Ok(response(
                    200,
                    "job_cancelled",
                    &serde_json::json!({ "id": body.id, "cancelled": true }),
                ))
            }
            ("GET", "/api/v1/audit/events") => {
                self.require(principal, Permission::ManageKeys)?;
                Ok(response(200, "audit", &self.audit_events()))
            }
            _ => {
                // Distinguish a known path with the wrong method from an unknown path.
                if ROUTES.iter().any(|(_, path)| *path == request.path) {
                    Err(ApiError::new(
                        405,
                        "method_not_allowed",
                        "method not allowed for this path",
                    ))
                } else {
                    Err(ApiError::new(404, "not_found", "unknown route"))
                }
            }
        }
    }

    fn route_webhooks(
        &self,
        request: &Request,
        principal: Option<&Principal>,
    ) -> Result<Response, ApiError> {
        self.require(principal, Permission::ManageWebhooks)?;
        match request.method.as_str() {
            "POST" => {
                let body: CreateWebhookRequest = parse_json(request)?;
                let events = parse_webhook_events(&body.events)?;
                let created = self
                    .webhooks
                    .write()
                    .expect("webhook store poisoned")
                    .create(&body.url, &events)
                    .map_err(ApiError::from)?;
                Ok(response(201, "webhook", &created))
            }
            "GET" => {
                let subscriptions = self.webhooks.read().expect("webhook store poisoned").list();
                Ok(response(200, "webhooks", &subscriptions))
            }
            _ => Err(method_not_allowed()),
        }
    }

    fn route_webhook_item(
        &self,
        request: &Request,
        principal: Option<&Principal>,
        id: &str,
    ) -> Result<Response, ApiError> {
        if id.is_empty() || id.contains('/') {
            return Err(webhook_not_found());
        }
        self.require(principal, Permission::ManageWebhooks)?;
        match request.method.as_str() {
            "GET" => {
                let subscription = self
                    .webhooks
                    .read()
                    .expect("webhook store poisoned")
                    .get(id);
                subscription
                    .map(|subscription| response(200, "webhook", &subscription))
                    .ok_or_else(webhook_not_found)
            }
            "PATCH" => {
                let body: UpdateWebhookRequest = parse_json(request)?;
                let events = match body.events.as_deref() {
                    Some(values) => Some(parse_webhook_events(values)?),
                    None => None,
                };
                let updated = self
                    .webhooks
                    .write()
                    .expect("webhook store poisoned")
                    .update(id, body.url.as_deref(), events.as_deref(), body.active)
                    .map_err(ApiError::from)?;
                updated
                    .map(|subscription| response(200, "webhook", &subscription))
                    .ok_or_else(webhook_not_found)
            }
            "DELETE" => {
                let removed = self
                    .webhooks
                    .write()
                    .expect("webhook store poisoned")
                    .delete(id);
                if removed {
                    Ok(response(
                        200,
                        "webhook_deleted",
                        &serde_json::json!({ "id": id, "deleted": true }),
                    ))
                } else {
                    Err(webhook_not_found())
                }
            }
            _ => Err(method_not_allowed()),
        }
    }
}

fn method_not_allowed() -> ApiError {
    ApiError::new(
        405,
        "method_not_allowed",
        "method not allowed for this path",
    )
}

fn webhook_not_found() -> ApiError {
    ApiError::new(404, "not_found", "unknown webhook subscription")
}

fn parse_webhook_events(values: &[String]) -> Result<Vec<WebhookEvent>, ApiError> {
    if values.is_empty() {
        return Err(ApiError::bad_request(
            "a webhook subscription must select at least one event",
        ));
    }
    values
        .iter()
        .map(|value| WebhookEvent::parse(value).map_err(ApiError::from))
        .collect()
}

fn query_value<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .query
        .as_deref()?
        .split('&')
        .find_map(|pair| match pair.split_once('=') {
            Some((key, value)) if key == name => Some(value),
            _ => None,
        })
}

fn wants_json(request: &Request) -> bool {
    request.query.as_deref().is_some_and(|query| {
        query
            .split('&')
            .any(|pair| pair.eq_ignore_ascii_case("format=json"))
    })
}

fn parse_json<T: serde::de::DeserializeOwned>(request: &Request) -> Result<T, ApiError> {
    if !request.body.is_empty() && request.header("content-type") != Some("application/json") {
        // Be lenient only about a missing content-type; reject explicit non-JSON.
        if let Some(value) = request.header("content-type") {
            if !value.contains("json") {
                return Err(ApiError::new(
                    415,
                    "unsupported_media_type",
                    "Content-Type must be application/json",
                ));
            }
        }
    }
    serde_json::from_slice(&request.body)
        .map_err(|error| ApiError::bad_request(format!("invalid JSON body: {error}")))
}

fn response<T: Serialize>(status: u16, kind: &str, data: &T) -> Response {
    match report(kind, data).to_json() {
        Ok(json) => {
            let value: Value = serde_json::from_str(&json).unwrap_or(Value::Null);
            Response::json(status, &value)
        }
        Err(_) => error_response(500, "internal", "report serialization failed"),
    }
}

fn error_response(status: u16, code: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "kind": "error",
        "code": code,
        "message": message,
    });
    Response::json(status, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Request;
    use base64::Engine as _;
    use observatory_testutil::module_with_spec;
    use observatory_testutil::spec::{spec_function, spec_struct};
    use std::collections::BTreeMap;
    use stellar_xdr::{ScSpecEntry, ScSpecTypeDef};

    fn post(path: &str, body: Value) -> Request {
        Request {
            method: "POST".to_string(),
            path: path.to_string(),
            query: None,
            headers: BTreeMap::new(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    fn get(path: &str) -> Request {
        Request {
            method: "GET".to_string(),
            path: path.to_string(),
            query: None,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    fn contract() -> String {
        let module = module_with_spec(&[
            spec_function("hello", &[], Some(ScSpecTypeDef::Bool)),
            spec_struct("S", &[("a", ScSpecTypeDef::U32)]),
        ]);
        base64::engine::general_purpose::STANDARD.encode(module)
    }

    fn empty_contract() -> String {
        base64::engine::general_purpose::STANDARD.encode(module_with_spec(&[] as &[ScSpecEntry]))
    }

    fn api_with_developer() -> (Api, String) {
        let api = Api::new(PlatformConfig::default());
        let key = api.generate_key(Role::Developer, "test").unwrap();
        (api, key)
    }

    fn with_key(mut request: Request, key: &str) -> Request {
        request
            .headers
            .insert("authorization".to_string(), format!("Bearer {key}"));
        request
    }

    #[test]
    fn public_health_and_version_do_not_require_auth() {
        let api = Api::new(PlatformConfig::default());
        assert_eq!(api.handle(&get("/api/v1/health"), "ip", 0).status, 200);
        let version = api.handle(&get("/api/v1/version"), "ip", 0);
        assert_eq!(version.status, 200);
        assert!(String::from_utf8_lossy(&version.body).contains("\"api_version\":\"v1\""));
    }

    #[test]
    fn analysis_requires_authentication() {
        let api = Api::new(PlatformConfig::default());
        let request = post(
            "/api/v1/contracts/inspect",
            serde_json::json!({ "wasm_base64": contract() }),
        );
        let response = api.handle(&request, "ip", 0);
        assert_eq!(response.status, 401);
    }

    #[test]
    fn developer_can_inspect() {
        let (api, key) = api_with_developer();
        let request = with_key(
            post(
                "/api/v1/contracts/inspect",
                serde_json::json!({ "wasm_base64": contract() }),
            ),
            &key,
        );
        let response = api.handle(&request, "ip", 0);
        assert_eq!(response.status, 200);
        assert!(response
            .headers
            .iter()
            .any(|(name, _)| name == "X-Request-Id"));
        assert!(String::from_utf8_lossy(&response.body).contains("\"has_contract_spec\":true"));
    }

    #[test]
    fn viewer_is_forbidden_from_analysis() {
        let api = Api::new(PlatformConfig::default());
        let key = api.generate_key(Role::Viewer, "readonly").unwrap();
        let request = with_key(
            post(
                "/api/v1/contracts/spec",
                serde_json::json!({ "wasm_base64": contract() }),
            ),
            &key,
        );
        assert_eq!(api.handle(&request, "ip", 0).status, 403);
    }

    #[test]
    fn compatibility_reports_incompatible() {
        let (api, key) = api_with_developer();
        let old = empty_contract();
        let new = contract();
        let request = with_key(
            post(
                "/api/v1/contracts/compatibility",
                serde_json::json!({ "old_wasm_base64": old, "new_wasm_base64": new, "policy": "strict" }),
            ),
            &key,
        );
        let response = api.handle(&request, "ip", 0);
        assert_eq!(response.status, 200);
        assert!(String::from_utf8_lossy(&response.body).contains("\"status\":\"unknown\""));
    }

    #[test]
    fn invalid_wasm_is_a_client_error() {
        let (api, key) = api_with_developer();
        let request = with_key(
            post(
                "/api/v1/contracts/inspect",
                serde_json::json!({ "wasm_base64": "AA==" }),
            ),
            &key,
        );
        assert_eq!(api.handle(&request, "ip", 0).status, 400);
    }

    #[test]
    fn unknown_route_and_wrong_method() {
        let api = Api::new(PlatformConfig::default());
        assert_eq!(api.handle(&get("/api/v1/nope"), "ip", 0).status, 404);
        assert_eq!(
            api.handle(&get("/api/v1/contracts/inspect"), "ip", 0)
                .status,
            405
        );
    }

    #[test]
    fn rate_limit_returns_429_with_headers() {
        let config = PlatformConfig {
            require_auth: false,
            rate_limit: observatory_platform::RateLimitConfig {
                limit: 1,
                window_secs: 60,
            },
            cors: observatory_platform::CorsConfig::default(),
        };
        let api = Api::new(config);
        assert_eq!(api.handle(&get("/api/v1/health"), "ip", 0).status, 200);
        let second = api.handle(&get("/api/v1/health"), "ip", 0);
        assert_eq!(second.status, 429);
        assert!(second
            .headers
            .iter()
            .any(|(name, value)| name == "X-RateLimit-Limit" && value == "1"));
    }

    #[test]
    fn missing_artifact_field_is_a_bad_request() {
        let (api, key) = api_with_developer();
        let request = with_key(post("/api/v1/contracts/spec", serde_json::json!({})), &key);
        assert_eq!(api.handle(&request, "ip", 0).status, 400);
    }

    fn metrics_snapshot(api: &Api) -> serde_json::Value {
        let mut request = get(METRICS_PATH);
        request.query = Some("format=json".to_string());
        let response = api.handle(&request, "ip", 0);
        assert_eq!(response.status, 200);
        serde_json::from_slice(&response.body).unwrap()
    }

    #[test]
    fn metrics_are_exposed_as_valid_prometheus_text() {
        let api = Api::new(PlatformConfig::default());
        assert_eq!(api.handle(&get("/api/v1/health"), "ip", 0).status, 200);
        let response = api.handle(&get(METRICS_PATH), "ip", 0);
        assert_eq!(response.status, 200);
        let content_type = &response
            .headers
            .iter()
            .find(|(name, _)| name == "Content-Type")
            .expect("metrics response has a content type")
            .1;
        assert!(content_type.starts_with("text/plain"));
        assert!(content_type.contains("version=0.0.4"));

        let text = String::from_utf8(response.body).unwrap();
        assert!(text.ends_with('\n'), "exposition must end with a newline");

        let mut counters = BTreeMap::new();
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let name = parts.next().expect("metric name");
            let value: u64 = parts
                .next()
                .expect("metric value")
                .parse()
                .expect("integer metric value");
            assert!(
                parts.next().is_none(),
                "unexpected trailing fields in {line:?}"
            );
            assert!(
                name.starts_with("observatory_api_"),
                "unexpected metric {name}"
            );
            counters.insert(name.to_string(), value);
        }
        assert_eq!(
            counters.get("observatory_api_requests_total"),
            Some(&2),
            "health plus the metrics scrape itself"
        );
        assert!(counters.contains_key("observatory_api_analyses_total"));
        assert!(counters.contains_key("observatory_api_errors_total"));
        assert!(counters.contains_key("observatory_api_rate_limited_total"));
        assert!(text.contains("# TYPE observatory_api_requests_total counter"));
        assert!(text.contains("# HELP observatory_api_requests_total"));
    }

    #[test]
    fn metrics_json_matches_the_counters() {
        let api = Api::new(PlatformConfig::default());
        assert_eq!(api.handle(&get(METRICS_PATH), "ip", 0).status, 200);
        let value = metrics_snapshot(&api);
        assert_eq!(value["kind"], "metrics");
        assert_eq!(value["data"]["requests_total"], 2);
        assert_eq!(value["tool"], TOOL_NAME);
    }

    #[test]
    fn metrics_count_analyses_and_clients_errors() {
        let (api, key) = api_with_developer();
        let request = with_key(
            post(
                "/api/v1/contracts/inspect",
                serde_json::json!({ "wasm_base64": contract() }),
            ),
            &key,
        );
        assert_eq!(api.handle(&request, "ip", 0).status, 200);
        assert_eq!(api.handle(&get("/api/v1/nope"), "ip", 0).status, 404);
        let value = metrics_snapshot(&api);
        assert_eq!(value["data"]["analyses_total"], 1);
        assert_eq!(value["data"]["errors_total"], 1);
        assert_eq!(value["data"]["rate_limited_total"], 0);
    }

    #[test]
    fn metrics_never_contain_api_keys() {
        let (api, key) = api_with_developer();
        let text = String::from_utf8(api.handle(&get(METRICS_PATH), "ip", 0).body).unwrap();
        assert!(!text.contains(&key));
        assert!(!text.contains("sco_"));
    }

    fn get_query(path: &str, query: &str) -> Request {
        Request {
            method: "GET".to_string(),
            path: path.to_string(),
            query: Some(query.to_string()),
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    fn events_fixture() -> Value {
        serde_json::json!({
            "events": [
                { "contractId": "CAAA", "type": "contract", "topics": [], "data": null },
                { "type": "system", "topics": [], "data": null },
                { "contractId": "CBBB", "type": "contract", "topics": [], "data": null }
            ]
        })
    }

    #[test]
    fn events_endpoint_filters_and_bounds_results() {
        let (api, key) = api_with_developer();
        let request = with_key(
            post(
                "/api/v1/contracts/events",
                serde_json::json!({ "fixture": events_fixture() }),
            ),
            &key,
        );
        let response = api.handle(&request, "ip", 0);
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["data"].as_array().unwrap().len(), 3);

        let filtered = with_key(
            post(
                "/api/v1/contracts/events",
                serde_json::json!({ "fixture": events_fixture(), "type": "system" }),
            ),
            &key,
        );
        let body: Value = serde_json::from_slice(&api.handle(&filtered, "ip", 0).body).unwrap();
        assert_eq!(body["data"].as_array().unwrap().len(), 1);

        let limited = with_key(
            post(
                "/api/v1/contracts/events",
                serde_json::json!({ "fixture": events_fixture(), "limit": 2 }),
            ),
            &key,
        );
        let body: Value = serde_json::from_slice(&api.handle(&limited, "ip", 0).body).unwrap();
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn events_endpoint_rejects_malformed_fixtures_and_limits() {
        let (api, key) = api_with_developer();
        for body in [
            serde_json::json!({ "fixture": { "foo": 1 } }),
            serde_json::json!({ "fixture": [], "limit": 0 }),
            serde_json::json!({ "fixture": [], "limit": 5000 }),
        ] {
            let request = with_key(post("/api/v1/contracts/events", body), &key);
            assert_eq!(api.handle(&request, "ip", 0).status, 400);
        }
    }

    #[test]
    fn jobs_are_idempotent_observable_and_cancellable() {
        let (api, key) = api_with_developer();
        let body = serde_json::json!({ "kind": "analysis", "idempotency_key": "k1" });
        let first = api.handle(&with_key(post("/api/v1/jobs", body.clone()), &key), "ip", 1);
        assert_eq!(first.status, 201);
        let first_body: Value = serde_json::from_slice(&first.body).unwrap();
        let id = first_body["data"]["id"].as_str().unwrap().to_string();

        let second = api.handle(&with_key(post("/api/v1/jobs", body), &key), "ip", 2);
        assert_eq!(second.status, 201);
        let second_body: Value = serde_json::from_slice(&second.body).unwrap();
        assert_eq!(second_body["data"]["id"], id);

        let status = api.handle(
            &with_key(get_query("/api/v1/jobs", &format!("id={id}")), &key),
            "ip",
            3,
        );
        assert_eq!(status.status, 200);
        let status_body: Value = serde_json::from_slice(&status.body).unwrap();
        assert_eq!(status_body["data"]["state"], "queued");

        let cancel = api.handle(
            &with_key(
                post("/api/v1/jobs/cancel", serde_json::json!({ "id": id })),
                &key,
            ),
            "ip",
            4,
        );
        assert_eq!(cancel.status, 200);
        let cancelled = api.handle(
            &with_key(get_query("/api/v1/jobs", &format!("id={id}")), &key),
            "ip",
            5,
        );
        let cancelled_body: Value = serde_json::from_slice(&cancelled.body).unwrap();
        assert_eq!(cancelled_body["data"]["state"], "cancelled");
        assert_eq!(
            api.handle(
                &with_key(
                    post("/api/v1/jobs/cancel", serde_json::json!({ "id": id })),
                    &key,
                ),
                "ip",
                6,
            )
            .status,
            400
        );
    }

    #[test]
    fn audit_log_records_privileged_actions_without_secrets() {
        let api = Api::new(PlatformConfig::default());
        let admin = api.generate_key(Role::Admin, "admin").unwrap();
        let serialized = serde_json::to_string(&api.audit_events()).unwrap();
        assert!(serialized.contains("key.create"));
        assert!(!serialized.contains(&admin));
        assert!(!serialized.contains("sco_"));

        let inspect = with_key(
            post(
                "/api/v1/contracts/inspect",
                serde_json::json!({ "wasm_base64": contract() }),
            ),
            &admin,
        );
        assert_eq!(api.handle(&inspect, "ip", 1).status, 200);
        assert_eq!(
            api.handle(&inspect, "ip", 2).status,
            200,
            "rate limit has room"
        );
        assert!(api
            .audit_events()
            .iter()
            .any(|e| e.action == "analysis.run"));
        assert_eq!(
            api.handle(
                &post(
                    "/api/v1/contracts/inspect",
                    serde_json::json!({ "wasm_base64": contract() }),
                ),
                "ip",
                3,
            )
            .status,
            401
        );
        assert!(api
            .audit_events()
            .iter()
            .any(|e| e.action == "auth.failure"));

        let developer = api.generate_key(Role::Developer, "dev").unwrap();
        assert_eq!(
            api.handle(&with_key(get("/api/v1/audit/events"), &developer), "ip", 4,)
                .status,
            403
        );
        assert_eq!(
            api.handle(&with_key(get("/api/v1/audit/events"), &admin), "ip", 5)
                .status,
            200
        );
    }

    fn maintainer_api() -> (Api, String) {
        let api = Api::new(PlatformConfig::default());
        let key = api.generate_key(Role::Maintainer, "hooks").unwrap();
        (api, key)
    }

    fn webhook_body() -> Value {
        serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["analysis_completed", "analysis_failed"]
        })
    }

    fn created_id(response: &Response) -> String {
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        value["data"]["id"].as_str().unwrap().to_string()
    }

    #[test]
    fn maintainer_can_manage_webhooks() {
        let (api, key) = maintainer_api();
        let create = with_key(post("/api/v1/webhooks", webhook_body()), &key);
        let response = api.handle(&create, "ip", 0);
        assert_eq!(response.status, 201);
        let body = String::from_utf8_lossy(&response.body);
        assert!(body.contains("\"secret\""));
        let id = created_id(&response);

        let get = with_key(get_request(&format!("/api/v1/webhooks/{id}")), &key);
        let got = api.handle(&get, "ip", 0);
        assert_eq!(got.status, 200);
        assert!(!String::from_utf8_lossy(&got.body).contains("\"secret\""));

        let list = with_key(get_request("/api/v1/webhooks"), &key);
        let listed = api.handle(&list, "ip", 0);
        assert_eq!(listed.status, 200);
        assert!(!String::from_utf8_lossy(&listed.body).contains("\"secret\""));

        let mut patch = post(
            &format!("/api/v1/webhooks/{id}"),
            serde_json::json!({ "active": false }),
        );
        patch.method = "PATCH".to_string();
        let patched = api.handle(&with_key(patch, &key), "ip", 0);
        assert_eq!(patched.status, 200);
        assert!(String::from_utf8_lossy(&patched.body).contains("\"active\":false"));

        let mut delete = get_request(&format!("/api/v1/webhooks/{id}"));
        delete.method = "DELETE".to_string();
        assert_eq!(api.handle(&with_key(delete, &key), "ip", 0).status, 200);
        let mut again = get_request(&format!("/api/v1/webhooks/{id}"));
        again.method = "DELETE".to_string();
        assert_eq!(api.handle(&with_key(again, &key), "ip", 0).status, 404);
    }

    #[test]
    fn webhook_registration_rejects_invalid_urls() {
        let (api, key) = maintainer_api();
        let request = with_key(
            post(
                "/api/v1/webhooks",
                serde_json::json!({ "url": "http://internal/hook", "events": ["analysis_completed"] }),
            ),
            &key,
        );
        assert_eq!(api.handle(&request, "ip", 0).status, 400);

        let request = with_key(
            post(
                "/api/v1/webhooks",
                serde_json::json!({ "url": "https://user:pass@example.com", "events": ["analysis_completed"] }),
            ),
            &key,
        );
        assert_eq!(api.handle(&request, "ip", 0).status, 400);
    }

    #[test]
    fn webhook_registration_requires_permission() {
        let (api, key) = api_with_developer();
        let request = with_key(post("/api/v1/webhooks", webhook_body()), &key);
        assert_eq!(api.handle(&request, "ip", 0).status, 403);
    }

    fn get_request(path: &str) -> Request {
        get(path)
    }

    fn cors_api(origins: &[&str]) -> Api {
        let mut config = PlatformConfig::default();
        config.cors.allowed_origins = origins.iter().map(|origin| (*origin).to_string()).collect();
        Api::new(config)
    }

    fn with_origin(mut request: Request, origin: &str) -> Request {
        request
            .headers
            .insert("origin".to_string(), origin.to_string());
        request
    }

    fn header_value<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn cors_denies_cross_origin_by_default() {
        let api = Api::new(PlatformConfig::default());
        let request = with_origin(get("/api/v1/health"), "https://app.example.com");
        let response = api.handle(&request, "ip", 0);
        assert_eq!(response.status, 200);
        assert!(header_value(&response, "Access-Control-Allow-Origin").is_none());
    }

    #[test]
    fn cors_echoes_allowed_origins_only() {
        let api = cors_api(&["https://app.example.com"]);
        let allowed = with_origin(get("/api/v1/health"), "https://app.example.com");
        let response = api.handle(&allowed, "ip", 0);
        assert_eq!(
            header_value(&response, "Access-Control-Allow-Origin"),
            Some("https://app.example.com")
        );

        let denied = with_origin(get("/api/v1/health"), "https://evil.example.com");
        let response = api.handle(&denied, "ip", 0);
        assert!(header_value(&response, "Access-Control-Allow-Origin").is_none());
    }

    #[test]
    fn cors_preflight_for_allowed_origin() {
        let api = cors_api(&["https://app.example.com"]);
        let mut request = get("/api/v1/contracts/inspect");
        request.method = "OPTIONS".to_string();
        request
            .headers
            .insert("origin".to_string(), "https://app.example.com".to_string());
        request.headers.insert(
            "access-control-request-method".to_string(),
            "POST".to_string(),
        );
        let response = api.handle(&request, "ip", 0);
        assert_eq!(response.status, 204);
        assert_eq!(
            header_value(&response, "Access-Control-Allow-Origin"),
            Some("https://app.example.com")
        );
        assert!(header_value(&response, "Access-Control-Allow-Methods").is_some());
        assert!(header_value(&response, "Access-Control-Allow-Credentials").is_none());
    }

    #[test]
    fn cors_preflight_for_disallowed_origin() {
        let api = cors_api(&["https://app.example.com"]);
        let mut request = get("/api/v1/contracts/inspect");
        request.method = "OPTIONS".to_string();
        request
            .headers
            .insert("origin".to_string(), "https://evil.example.com".to_string());
        let response = api.handle(&request, "ip", 0);
        assert_eq!(response.status, 403);
        assert!(header_value(&response, "Access-Control-Allow-Origin").is_none());
    }
}
