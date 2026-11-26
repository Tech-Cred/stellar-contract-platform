//! Versioned REST router with authentication, authorization, and rate limiting.
//!
//! The router is transport-agnostic: [`Api::handle`] takes a parsed [`Request`]
//! and returns a [`Response`]. The HTTP adapter in `crate::http` is a thin
//! wrapper, so the routing logic is fully unit-testable without sockets.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use observatory_core::error::redact_secrets;
use observatory_core::hash::sha256_hex;
use observatory_core::{ObservatoryError, Result as CoreResult, SCHEMA_VERSION, TOOL_NAME};
use observatory_output::report;
use observatory_platform::{
    authorize_with_scopes, validate_scopes, ApiKeyRecord, ApiKeyStore, AuditEvent, AuditLog,
    AuthFailureReason, CompatibilityPolicy, JobQueue, KeyRotation, KeyStore, Observatory,
    Permission, PlatformConfig, Principal, RateLimitReason, RateLimiter, Role, WebhookEvent,
    WebhookStore,
};
use serde::Serialize;
use serde_json::Value;

use crate::dto::{
    decode_wasm, CancelJobRequest, CompatibilityRequest, CreateJobRequest, CreateKeyRequest,
    CreateWebhookRequest, DiffRequest, EventsRequest, InspectRequest, RotateKeyRequest,
    UpdateWebhookRequest, WasmRequest,
};
use crate::errors::entry as error_entry;
use crate::http::{Request, Response};
use crate::metrics::{self, Metrics};
use crate::pagination::{page_of, PageRequest};

/// The API version prefix.
pub const API_PREFIX: &str = "/api/v1";

/// The Prometheus metrics endpoint path.
pub const METRICS_PATH: &str = "/api/v1/metrics";

/// The machine-readable error catalog endpoint path.
pub const ERRORS_PATH: &str = "/api/v1/errors";

/// The declared routes: `(method, path)`. Used by the router and by the
/// OpenAPI synchronization test.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/readiness"),
    ("GET", "/api/v1/version"),
    ("GET", METRICS_PATH),
    ("GET", ERRORS_PATH),
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
    ("POST", "/api/v1/keys"),
    ("GET", "/api/v1/keys"),
    ("DELETE", "/api/v1/keys/{id}"),
    ("POST", "/api/v1/keys/{id}/rotate"),
    ("POST", "/api/v1/webhooks"),
    ("GET", "/api/v1/webhooks"),
    ("GET", "/api/v1/webhooks/{id}"),
    ("PATCH", "/api/v1/webhooks/{id}"),
    ("DELETE", "/api/v1/webhooks/{id}"),
];

/// Maximum number of events returned by one `/contracts/events` request.
pub const MAX_EVENT_RESULTS: usize = 1000;

/// How long an idempotent response is retained, in seconds.
pub const IDEMPOTENCY_TTL_SECS: u64 = 300;

/// Maximum number of cached idempotent responses.
///
/// The oldest entry is evicted when the bound is reached, so a burst of unique
/// keys cannot grow memory without limit.
pub const MAX_IDEMPOTENCY_ENTRIES: usize = 128;

/// Maximum accepted `Idempotency-Key` length in bytes.
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;

#[derive(Debug, Clone)]
struct IdempotentResponse {
    fingerprint: String,
    response: Response,
    stored_at: u64,
}

#[derive(Debug, Default)]
struct IdempotencyCache {
    entries: BTreeMap<String, IdempotentResponse>,
}

enum IdempotencyLookup {
    Replay(Response),
    Conflict,
    Miss,
}

impl IdempotencyCache {
    fn lookup(&mut self, scope: &str, fingerprint: &str, now_secs: u64) -> IdempotencyLookup {
        match self.entries.get(scope) {
            Some(entry) if now_secs.saturating_sub(entry.stored_at) >= IDEMPOTENCY_TTL_SECS => {
                self.entries.remove(scope);
                IdempotencyLookup::Miss
            }
            Some(entry) if entry.fingerprint == fingerprint => {
                IdempotencyLookup::Replay(entry.response.clone())
            }
            Some(_) => IdempotencyLookup::Conflict,
            None => IdempotencyLookup::Miss,
        }
    }

    fn remember(&mut self, scope: String, fingerprint: String, response: &Response, now_secs: u64) {
        self.entries
            .retain(|_, entry| now_secs.saturating_sub(entry.stored_at) < IDEMPOTENCY_TTL_SECS);
        while self.entries.len() >= MAX_IDEMPOTENCY_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.stored_at)
                .map(|(scope, _)| scope.clone());
            match oldest {
                Some(scope) => {
                    self.entries.remove(&scope);
                }
                None => break,
            }
        }
        self.entries.insert(
            scope,
            IdempotentResponse {
                fingerprint,
                response: response.clone(),
                stored_at: now_secs,
            },
        );
    }
}

fn is_mutating(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

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
    /// Build an error from the catalog.
    ///
    /// The status always comes from [`crate::errors::ERROR_CATALOG`], so a
    /// response cannot disagree with the published catalog. A code missing from
    /// the catalog is a programming error and panics during tests.
    fn new(code: &str, message: impl Into<String>) -> Self {
        let entry = error_entry(code)
            .unwrap_or_else(|| panic!("error code `{code}` is missing from the catalog"));
        ApiError {
            status: entry.status,
            code: code.to_string(),
            message: message.into(),
        }
    }

    fn unauthorized() -> Self {
        ApiError::new("unauthorized", "a valid API key is required")
    }

    fn forbidden() -> Self {
        ApiError::new("forbidden", "the API key lacks the required permission")
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        ApiError::new("bad_request", message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        ApiError::new("not_found", message)
    }
}

impl From<ObservatoryError> for ApiError {
    fn from(error: ObservatoryError) -> Self {
        ApiError::new(error.code().as_str(), error.to_string())
    }
}

/// The authentication state for one request.
///
/// The failure reason is carried alongside the absent principal so it is only
/// counted when a route actually requires authentication. The reason is a
/// fixed enum, so no supplied credential can be retained by the metrics layer.
#[derive(Debug)]
struct AuthContext {
    principal: Option<Principal>,
    failure: Option<AuthFailureReason>,
}

impl AuthContext {
    fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
    }

    fn key_id(&self) -> Option<&str> {
        self.principal().map(|principal| principal.key_id.as_str())
    }

    fn failure_reason(&self) -> AuthFailureReason {
        self.failure.unwrap_or(AuthFailureReason::MissingKey)
    }
}

/// The API application.
pub struct Api {
    observatory: Observatory,
    keys: RwLock<Box<dyn KeyStore>>,
    audit: RwLock<AuditLog>,
    jobs: RwLock<JobQueue>,
    webhooks: RwLock<WebhookStore>,
    limiter: RateLimiter,
    config: PlatformConfig,
    counter: AtomicU64,
    metrics: Metrics,
    idempotency: RwLock<IdempotencyCache>,
}

impl Api {
    /// Create an API with the given configuration and no keys.
    #[must_use]
    pub fn new(config: PlatformConfig) -> Self {
        Self::with_key_store(config, Box::new(ApiKeyStore::new()))
    }

    /// Create an API backed by an explicit key store.
    ///
    /// Use this to plug in [`observatory_platform::FileKeyStore`] so keys
    /// survive a restart.
    #[must_use]
    pub fn with_key_store(config: PlatformConfig, keys: Box<dyn KeyStore>) -> Self {
        let limiter = RateLimiter::new(config.rate_limit);
        Api {
            observatory: Observatory::new(),
            keys: RwLock::new(keys),
            audit: RwLock::new(AuditLog::default()),
            jobs: RwLock::new(JobQueue::new(2)),
            webhooks: RwLock::new(WebhookStore::new()),
            limiter,
            config,
            counter: AtomicU64::new(0),
            metrics: Metrics::new(),
            idempotency: RwLock::new(IdempotencyCache::default()),
        }
    }

    /// Retained audit events, oldest first.
    #[must_use]
    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.audit.read().expect("audit log poisoned").snapshot()
    }

    /// The retained audit events, redacted, oldest first.
    ///
    /// The audit log is built to carry no secrets; the redaction pass is
    /// defense in depth for the read path.
    fn redacted_audit_events(&self) -> Vec<AuditEvent> {
        self.audit_events()
            .into_iter()
            .map(|mut event| {
                event.actor = event.actor.map(|value| redact_secrets(&value));
                event.action = redact_secrets(&event.action);
                event.resource = redact_secrets(&event.resource);
                event.outcome = redact_secrets(&event.outcome);
                event.request_id = event.request_id.map(|value| redact_secrets(&value));
                event
            })
            .collect()
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
            keys.generate(role, label, None)?
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
        let id = id.into();
        let hash = hash.into();
        let mut keys = self.keys.write().expect("key store poisoned");
        keys.insert_hashed(&id, &hash, role, label);
    }

    /// Register a key from its plaintext form (`sco_<id>_<secret>`).
    pub fn insert_plaintext_key(&self, plaintext: &str, role: Role, label: &str) -> CoreResult<()> {
        let mut keys = self.keys.write().expect("key store poisoned");
        keys.insert_plaintext(plaintext, role, label)?;
        Ok(())
    }

    /// Key metadata, sorted by id. Never includes hashes or plaintext.
    #[must_use]
    pub fn list_keys(&self) -> Vec<ApiKeyRecord> {
        let keys = self.keys.read().expect("key store poisoned");
        keys.list()
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

    /// The role granted to a key, if it exists and is active.
    #[must_use]
    pub fn key_role(&self, id: &str) -> Option<Role> {
        self.keys
            .read()
            .expect("key store poisoned")
            .list()
            .into_iter()
            .find(|record| record.id == id && !record.revoked)
            .map(|record| record.role)
    }

    /// Rotate a key, returning the new plaintext exactly once.
    pub fn rotate_key(
        &self,
        id: &str,
        label: Option<&str>,
        scopes: Option<Vec<Permission>>,
        grace_period_secs: Option<u64>,
        now_secs: u64,
    ) -> CoreResult<Option<(String, KeyRotation)>> {
        let result = {
            let mut keys = self.keys.write().expect("key store poisoned");
            keys.rotate(id, label, scopes, grace_period_secs, now_secs)?
        };
        match &result {
            Some((_, rotation)) => self.record_audit(
                None,
                "key.rotate",
                &format!("key:{}:{}", rotation.old_id, rotation.new_record.id),
                "success",
                None,
                now_secs,
            ),
            None => self.record_audit(
                None,
                "key.rotate",
                &format!("key:{id}"),
                "failure",
                None,
                now_secs,
            ),
        }
        Ok(result)
    }

    /// Handle a request.
    #[must_use]
    pub fn handle(&self, request: &Request, client_id: &str, now_secs: u64) -> Response {
        // Request-level span; covers routing, authorization, and audit
        // recording. Fields are route metadata only, never artifact bytes.
        let span = tracing::info_span!(
            "http_request",
            method = %request.method,
            path = %request.path,
            client = %client_id,
        );
        let _span_guard = span.enter();
        let request_id = format!(
            "req-{:016x}",
            self.counter.fetch_add(1, Ordering::Relaxed) + 1
        );
        self.metrics.record_request();
        // A rotation grace period is evaluated lazily on the next request, so
        // the exact clock is supplied by the caller and stays testable.
        let expired = self
            .keys
            .write()
            .expect("key store poisoned")
            .revoke_expired(now_secs);
        for id in expired {
            self.record_audit(
                None,
                "key.revoke",
                &format!("key:{id}"),
                "grace_expired",
                Some(request_id.clone()),
                now_secs,
            );
        }
        let auth = self.principal(request);
        let rate_key = auth
            .key_id()
            .map(str::to_string)
            .unwrap_or_else(|| format!("client:{client_id}"));
        // Each route keeps its own window so a strict analysis limit cannot
        // starve cheap health checks for the same caller.
        let route_key = format!("{rate_key}|{}", request.path);
        let limit = self.config.rate_limit_for(&request.path);
        let decision = self.limiter.check_with(limit, &route_key, now_secs);
        let actor = auth.key_id().map(str::to_string);
        let idempotency_owner = actor
            .clone()
            .unwrap_or_else(|| format!("client:{client_id}"));

        if !decision.allowed {
            self.metrics
                .record_rate_limit_rejection(RateLimitReason::WindowExceeded);
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
            error_response(&ApiError::new("rate_limited", "rate limit exceeded"))
        } else if request.method == "OPTIONS" {
            self.preflight(request)
        } else if !accepts(request) {
            error_response(&ApiError::new(
                "not_acceptable",
                "Accept must allow a supported response media type",
            ))
        } else {
            match self.dispatch(request, &auth, now_secs, &request_id, &idempotency_owner) {
                Ok(response) => response,
                Err(error) => error_response(&error),
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

    fn dispatch(
        &self,
        request: &Request,
        auth: &AuthContext,
        now_secs: u64,
        request_id: &str,
        owner: &str,
    ) -> Result<Response, ApiError> {
        let Some((scope, fingerprint)) = self.idempotency_scope(request, owner)? else {
            return self.route(request, auth, now_secs, request_id);
        };

        let lookup = self
            .idempotency
            .write()
            .expect("idempotency cache poisoned")
            .lookup(&scope, &fingerprint, now_secs);
        match lookup {
            IdempotencyLookup::Replay(response) => {
                Ok(response.with_header("Idempotency-Replayed", "true"))
            }
            IdempotencyLookup::Conflict => Err(ApiError::new(
                "idempotency_conflict",
                "Idempotency-Key was already used for a different request",
            )),
            IdempotencyLookup::Miss => {
                let response = self.route(request, auth, now_secs, request_id)?;
                // Only successful work is cached; a retry of a failure should
                // be able to succeed once the cause is fixed.
                if (200..300).contains(&response.status) {
                    self.idempotency
                        .write()
                        .expect("idempotency cache poisoned")
                        .remember(scope, fingerprint, &response, now_secs);
                }
                Ok(response)
            }
        }
    }

    fn idempotency_scope(
        &self,
        request: &Request,
        owner: &str,
    ) -> Result<Option<(String, String)>, ApiError> {
        if !is_mutating(&request.method) {
            return Ok(None);
        }
        let Some(raw) = request.header("idempotency-key") else {
            return Ok(None);
        };
        let key = raw.trim();
        if key.is_empty() {
            return Err(ApiError::bad_request("Idempotency-Key must not be empty"));
        }
        if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(ApiError::bad_request(format!(
                "Idempotency-Key must be at most {MAX_IDEMPOTENCY_KEY_BYTES} bytes"
            )));
        }

        // The fingerprint covers everything that changes what the request does.
        let mut material = Vec::new();
        for part in [
            request.method.as_str(),
            request.path.as_str(),
            request.query.as_deref().unwrap_or_default(),
        ] {
            material.extend_from_slice(part.as_bytes());
            material.push(0);
        }
        material.extend_from_slice(&request.body);
        Ok(Some((format!("{owner}:{key}"), sha256_hex(&material))))
    }

    fn preflight(&self, request: &Request) -> Response {
        let Some(origin) = request.header("origin") else {
            return error_response(&ApiError::new(
                "bad_request",
                "preflight requires an Origin header",
            ));
        };
        if !self.config.cors.is_allowed_origin(origin) {
            return error_response(&ApiError::new(
                "cors_origin_denied",
                "origin is not allowed",
            ));
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

    fn principal(&self, request: &Request) -> AuthContext {
        let provided = request.header("x-api-key").map(str::to_string).or_else(|| {
            request
                .header("authorization")
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(str::to_string)
        });
        let Some(provided) = provided else {
            return AuthContext {
                principal: None,
                failure: self
                    .config
                    .require_auth
                    .then_some(AuthFailureReason::MissingKey),
            };
        };
        let keys = self.keys.read().expect("key store poisoned");
        let principal = keys.authenticate(&provided);
        let failure = if principal.is_none() && self.config.require_auth {
            Some(AuthFailureReason::InvalidKey)
        } else {
            None
        };
        AuthContext { principal, failure }
    }

    fn require(&self, auth: &AuthContext, permission: Permission) -> Result<(), ApiError> {
        if !self.config.require_auth {
            return Ok(());
        }
        let Some(principal) = auth.principal() else {
            self.metrics.record_auth_failure(auth.failure_reason());
            return Err(ApiError::unauthorized());
        };
        if authorize_with_scopes(principal.role, principal.scopes.as_deref(), permission) {
            Ok(())
        } else {
            self.metrics
                .record_auth_failure(AuthFailureReason::InsufficientPermission);
            Err(ApiError::forbidden())
        }
    }

    fn route(
        &self,
        request: &Request,
        auth: &AuthContext,
        now_secs: u64,
        request_id: &str,
    ) -> Result<Response, ApiError> {
        let actor = auth.key_id().map(str::to_string);
        if request.path == "/api/v1/webhooks" {
            return self.route_webhooks(request, auth);
        }
        if let Some(id) = request.path.strip_prefix("/api/v1/webhooks/") {
            return self.route_webhook_item(request, auth, id);
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
            ("GET", ERRORS_PATH) => Ok(response(
                200,
                "errors",
                &serde_json::json!({ "errors": crate::errors::ERROR_CATALOG }),
            )),
            ("POST", "/api/v1/keys") => {
                self.require(auth, Permission::ManageKeys)?;
                let body: CreateKeyRequest = parse_json(request)?;
                if body.label.trim().is_empty() {
                    return Err(ApiError::bad_request("label must not be empty"));
                }
                let role = Role::from_str(&body.role).map_err(ApiError::bad_request)?;
                let scopes = parse_scopes(role, body.scopes.as_deref())?;
                let (plaintext, record) = {
                    let mut keys = self.keys.write().expect("key store poisoned");
                    keys.generate(role, &body.label, scopes)
                        .map_err(ApiError::from)?
                };
                Ok(response(
                    201,
                    "api_key",
                    &serde_json::json!({
                        "id": record.id,
                        "role": record.role,
                        "scopes": record.scopes,
                        "label": record.label,
                        "plaintext": plaintext,
                        "note": "the plaintext key is shown once and cannot be retrieved again",
                    }),
                ))
            }
            ("GET", "/api/v1/keys") => {
                self.require(auth, Permission::ManageKeys)?;
                let page_request = PageRequest::parse(request)?;
                let page = page_of(self.list_keys(), page_request.skip, page_request.limit);
                Ok(response(200, "api_keys", &page))
            }
            ("POST", path) if path.starts_with("/api/v1/keys/") && path.ends_with("/rotate") => {
                self.require(auth, Permission::ManageKeys)?;
                let id = path
                    .strip_prefix("/api/v1/keys/")
                    .and_then(|rest| rest.strip_suffix("/rotate"))
                    .unwrap_or_default();
                if id.is_empty() || id.contains('/') {
                    return Err(ApiError::not_found("unknown API key"));
                }
                let body: RotateKeyRequest = parse_json(request)?;
                if !body.confirm {
                    return Err(ApiError::bad_request(
                        "rotation must be confirmed with `confirm: true`",
                    ));
                }
                if body
                    .label
                    .as_deref()
                    .is_some_and(|label| label.trim().is_empty())
                {
                    return Err(ApiError::bad_request("label must not be empty"));
                }
                let role = self
                    .key_role(id)
                    .ok_or_else(|| ApiError::not_found("unknown API key"))?;
                let scopes = parse_scopes(role, body.scopes.as_deref())?;
                let rotated = self
                    .rotate_key(
                        id,
                        body.label.as_deref(),
                        scopes,
                        body.grace_period_secs,
                        now_secs,
                    )
                    .map_err(ApiError::from)?;
                let Some((plaintext, rotation)) = rotated else {
                    return Err(ApiError::not_found("unknown API key"));
                };
                Ok(response(
                    200,
                    "api_key_rotation",
                    &serde_json::json!({
                        "old_id": rotation.old_id,
                        "id": rotation.new_record.id,
                        "role": rotation.new_record.role,
                        "scopes": rotation.new_record.scopes,
                        "label": rotation.new_record.label,
                        "plaintext": plaintext,
                        "grace_period_secs": rotation.grace_period_secs,
                        "old_key_revoked_at": rotation.revoke_at,
                        "note": "the new plaintext key is shown once and cannot be retrieved again",
                    }),
                ))
            }
            ("DELETE", path) if path.starts_with("/api/v1/keys/") => {
                self.require(auth, Permission::ManageKeys)?;
                let id = path.trim_start_matches("/api/v1/keys/");
                if id.is_empty() || id.contains('/') {
                    return Err(ApiError::not_found("unknown API key"));
                }
                if self.revoke_key(id) {
                    Ok(response(
                        200,
                        "api_key_revoked",
                        &serde_json::json!({ "id": id, "revoked": true }),
                    ))
                } else {
                    Err(ApiError::not_found("unknown API key"))
                }
            }
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
                self.require(auth, Permission::RunAnalysis)?;
                let body: InspectRequest = parse_json(request)?;
                let wasm = decode_wasm(&body.wasm_base64).map_err(ApiError::from)?;
                let outcome = self
                    .observatory
                    .inspect(&wasm, body.security)
                    .map_err(ApiError::from)?;
                Ok(response(200, "inspect", &outcome))
            }
            ("POST", "/api/v1/contracts/spec") => {
                self.require(auth, Permission::RunAnalysis)?;
                let body: WasmRequest = parse_json(request)?;
                let wasm = decode_wasm(&body.wasm_base64).map_err(ApiError::from)?;
                let outcome = self.observatory.spec(&wasm).map_err(ApiError::from)?;
                Ok(response(200, "spec", &outcome))
            }
            ("POST", "/api/v1/contracts/diff") => {
                self.require(auth, Permission::RunAnalysis)?;
                let body: DiffRequest = parse_json(request)?;
                let old = decode_wasm(&body.old_wasm_base64).map_err(ApiError::from)?;
                let new = decode_wasm(&body.new_wasm_base64).map_err(ApiError::from)?;
                let outcome = self.observatory.diff(&old, &new).map_err(ApiError::from)?;
                Ok(response(200, "diff", &outcome))
            }
            ("POST", "/api/v1/contracts/compatibility") => {
                self.require(auth, Permission::RunAnalysis)?;
                let body: CompatibilityRequest = parse_json(request)?;
                let policy = match body.policy.as_str() {
                    "strict" => CompatibilityPolicy::strict(),
                    "additive-only" | "additive_only" => CompatibilityPolicy::additive_only(),
                    "lenient" => CompatibilityPolicy::lenient(),
                    other => {
                        return Err(ApiError::bad_request(format!(
                            "unknown policy `{other}`; expected strict, additive-only, or lenient"
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
                self.require(auth, Permission::RunAnalysis)?;
                let body: WasmRequest = parse_json(request)?;
                let wasm = decode_wasm(&body.wasm_base64).map_err(ApiError::from)?;
                let outcome = self
                    .observatory
                    .fingerprint(&wasm)
                    .map_err(ApiError::from)?;
                Ok(response(200, "fingerprint", &outcome))
            }
            ("POST", "/api/v1/contracts/security") => {
                self.require(auth, Permission::RunAnalysis)?;
                let body: WasmRequest = parse_json(request)?;
                let wasm = decode_wasm(&body.wasm_base64).map_err(ApiError::from)?;
                let outcome = self.observatory.security(&wasm).map_err(ApiError::from)?;
                Ok(response(200, "security", &outcome))
            }
            ("POST", "/api/v1/contracts/events") => {
                self.require(auth, Permission::RunAnalysis)?;
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
                self.require(auth, Permission::RunAnalysis)?;
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
                self.require(auth, Permission::RunAnalysis)?;
                let queue = self.jobs.read().expect("job queue poisoned");
                if let Some(id) = query_value(request, "id") {
                    match queue.job(id) {
                        Some(job) => Ok(response(200, "job", job)),
                        None => Err(ApiError::new("not_found", "unknown job")),
                    }
                } else {
                    let page_request = PageRequest::parse(request)?;
                    let page = page_of(queue.jobs(), page_request.skip, page_request.limit);
                    Ok(response(200, "jobs", &page))
                }
            }
            ("POST", "/api/v1/jobs/cancel") => {
                self.require(auth, Permission::RunAnalysis)?;
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
                self.require(auth, Permission::ManageKeys)?;
                let page_request = PageRequest::parse(request)?;
                let page = page_of(
                    self.redacted_audit_events(),
                    page_request.skip,
                    page_request.limit,
                );
                Ok(response(200, "audit", &page))
            }
            _ => {
                // Distinguish a known path with the wrong method from an unknown path.
                if ROUTES.iter().any(|(_, path)| *path == request.path) {
                    Err(ApiError::new(
                        "method_not_allowed",
                        "method not allowed for this path",
                    ))
                } else {
                    Err(ApiError::new("not_found", "unknown route"))
                }
            }
        }
    }

    fn route_webhooks(&self, request: &Request, auth: &AuthContext) -> Result<Response, ApiError> {
        self.require(auth, Permission::ManageWebhooks)?;
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
                let page_request = PageRequest::parse(request)?;
                let subscriptions = self.webhooks.read().expect("webhook store poisoned").list();
                let page = page_of(subscriptions, page_request.skip, page_request.limit);
                Ok(response(200, "webhooks", &page))
            }
            _ => Err(method_not_allowed()),
        }
    }

    fn route_webhook_item(
        &self,
        request: &Request,
        auth: &AuthContext,
        id: &str,
    ) -> Result<Response, ApiError> {
        if id.is_empty() || id.contains('/') {
            return Err(webhook_not_found());
        }
        self.require(auth, Permission::ManageWebhooks)?;
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
    ApiError::new("method_not_allowed", "method not allowed for this path")
}

fn webhook_not_found() -> ApiError {
    ApiError::new("not_found", "unknown webhook subscription")
}

fn parse_scopes(
    role: Role,
    values: Option<&[String]>,
) -> Result<Option<Vec<Permission>>, ApiError> {
    let Some(values) = values else {
        return Ok(None);
    };
    let mut scopes = Vec::with_capacity(values.len());
    for value in values {
        scopes.push(Permission::from_str(value).map_err(ApiError::bad_request)?);
    }
    validate_scopes(role, &scopes).map_err(ApiError::bad_request)?;
    Ok(Some(scopes))
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

pub(crate) fn query_value<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
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

/// Whether the request's `Accept` header permits a response.
///
/// A missing or empty header, a wildcard, or an explicit `application/json`
/// (or `application/*`) is accepted. The metrics endpoint can also serve
/// Prometheus text. Any explicit unsupported media type is rejected.
fn accepts(request: &Request) -> bool {
    let Some(header) = request.header("accept") else {
        return true;
    };
    if header.trim().is_empty() {
        return true;
    }
    header.split(',').any(|range| {
        let media = range
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        match media.as_str() {
            "*/*" | "application/*" | "application/json" => true,
            "text/*" | "text/plain" => request.path == METRICS_PATH,
            _ => false,
        }
    })
}

fn parse_json<T: serde::de::DeserializeOwned>(request: &Request) -> Result<T, ApiError> {
    if !request.body.is_empty() && request.header("content-type") != Some("application/json") {
        // Be lenient only about a missing content-type; reject explicit non-JSON.
        if let Some(value) = request.header("content-type") {
            if !value.contains("json") {
                return Err(ApiError::new(
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
        Err(_) => error_response(&ApiError::new("internal", "report serialization failed")),
    }
}

fn error_response(error: &ApiError) -> Response {
    let body = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "kind": "error",
        "code": error.code,
        "message": error.message,
    });
    Response::json(error.status, &body)
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

    fn with_idempotency_key(mut request: Request, key: &str) -> Request {
        request
            .headers
            .insert("idempotency-key".to_string(), key.to_string());
        request
    }

    fn replay_header(response: &Response) -> bool {
        response
            .headers
            .iter()
            .any(|(name, value)| name == "Idempotency-Replayed" && value == "true")
    }

    #[test]
    fn idempotent_post_replays_the_prior_result() {
        let (api, key) = api_with_developer();
        let body = serde_json::json!({ "kind": "analysis" });
        let request = with_idempotency_key(with_key(post("/api/v1/jobs", body), &key), "job-1");

        let first = api.handle(&request, "ip", 1);
        assert_eq!(first.status, 201);
        assert!(!replay_header(&first));
        let first_id = created_id(&first);

        let replay = api.handle(&request, "ip", 2);
        assert_eq!(replay.status, 201);
        assert!(replay_header(&replay));
        assert_eq!(created_id(&replay), first_id);
    }

    #[test]
    fn idempotent_post_rejects_a_conflicting_reuse() {
        let (api, key) = api_with_developer();
        let first = with_idempotency_key(
            with_key(
                post("/api/v1/jobs", serde_json::json!({ "kind": "analysis" })),
                &key,
            ),
            "same-key",
        );
        assert_eq!(api.handle(&first, "ip", 1).status, 201);

        let conflict = with_idempotency_key(
            with_key(
                post("/api/v1/jobs", serde_json::json!({ "kind": "other" })),
                &key,
            ),
            "same-key",
        );
        let response = api.handle(&conflict, "ip", 2);
        assert_eq!(response.status, 409);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["code"], "idempotency_conflict");
    }

    #[test]
    fn idempotency_cache_is_bounded_and_expires() {
        let config = PlatformConfig {
            rate_limit: observatory_platform::RateLimitConfig {
                limit: 1000,
                window_secs: 60,
            },
            ..PlatformConfig::default()
        };
        let api = Api::new(config);
        let key = api.generate_key(Role::Developer, "test").unwrap();

        let mut first_id = String::new();
        for index in 0..=MAX_IDEMPOTENCY_ENTRIES {
            let request = with_idempotency_key(
                with_key(
                    post(
                        "/api/v1/jobs",
                        serde_json::json!({ "kind": format!("job-{index}") }),
                    ),
                    &key,
                ),
                &format!("key-{index}"),
            );
            let response = api.handle(&request, "ip", 0);
            assert_eq!(response.status, 201);
            if index == 0 {
                first_id = created_id(&response);
            }
        }

        // The first entry was evicted to make room for the newest one.
        let evicted = with_idempotency_key(
            with_key(
                post("/api/v1/jobs", serde_json::json!({ "kind": "job-0" })),
                &key,
            ),
            "key-0",
        );
        let response = api.handle(&evicted, "ip", 0);
        assert_eq!(response.status, 201);
        assert!(!replay_header(&response), "the oldest entry was evicted");
        assert_ne!(created_id(&response), first_id);

        // The newest entry replays within the window and expires after it.
        let newest = with_idempotency_key(
            with_key(
                post(
                    "/api/v1/jobs",
                    serde_json::json!({ "kind": format!("job-{MAX_IDEMPOTENCY_ENTRIES}") }),
                ),
                &key,
            ),
            &format!("key-{MAX_IDEMPOTENCY_ENTRIES}"),
        );
        assert!(replay_header(&api.handle(&newest, "ip", 10)));
        let expired = api.handle(&newest, "ip", 10 + IDEMPOTENCY_TTL_SECS);
        assert_eq!(expired.status, 201);
        assert!(!replay_header(&expired));
    }

    #[test]
    fn posts_without_a_key_are_not_cached_and_empty_keys_are_rejected() {
        let (api, key) = api_with_developer();
        let body = serde_json::json!({ "kind": "analysis" });
        let first = api.handle(&with_key(post("/api/v1/jobs", body.clone()), &key), "ip", 1);
        let second = api.handle(&with_key(post("/api/v1/jobs", body), &key), "ip", 2);
        assert_eq!(first.status, 201);
        assert_eq!(second.status, 201);
        assert_ne!(created_id(&first), created_id(&second));

        let empty = with_idempotency_key(
            with_key(
                post("/api/v1/jobs", serde_json::json!({ "kind": "analysis" })),
                &key,
            ),
            "   ",
        );
        assert_eq!(api.handle(&empty, "ip", 3).status, 400);
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
    fn error_catalog_endpoint_is_public_and_complete() {
        let api = Api::new(PlatformConfig::default());
        let response = api.handle(&get(ERRORS_PATH), "ip", 0);
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let errors = body["data"]["errors"].as_array().expect("errors array");
        assert_eq!(errors.len(), crate::errors::ERROR_CATALOG.len());
        for expected in crate::errors::ERROR_CATALOG {
            let published = errors
                .iter()
                .find(|entry| entry["code"] == expected.code)
                .unwrap_or_else(|| panic!("{} missing from endpoint", expected.code));
            assert_eq!(
                published["status"].as_u64(),
                Some(u64::from(expected.status))
            );
            assert_eq!(published["retryable"].as_bool(), Some(expected.retryable));
            assert!(
                published["description"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty()),
                "{} has no description",
                expected.code
            );
        }
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
    fn additive_only_policy_accepts_additions_in_the_api() {
        let (api, key) = api_with_developer();
        let old = base64::engine::general_purpose::STANDARD
            .encode(module_with_spec(&[spec_function("hello", &[], None)]));
        let new = base64::engine::general_purpose::STANDARD.encode(module_with_spec(&[
            spec_function("hello", &[], None),
            spec_function("added", &[], None),
        ]));
        let request = with_key(
            post(
                "/api/v1/contracts/compatibility",
                serde_json::json!({
                    "old_wasm_base64": old,
                    "new_wasm_base64": new,
                    "policy": "additive-only",
                }),
            ),
            &key,
        );
        let response = api.handle(&request, "ip", 0);
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["data"]["status"], "compatible");
        assert_eq!(body["data"]["policy"]["function_removal_is_breaking"], true);
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
            ..PlatformConfig::default()
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

    #[test]
    fn authentication_failures_increment_reason_counters() {
        let api = Api::new(PlatformConfig::default());
        let body = serde_json::json!({ "kind": "analysis" });
        assert_eq!(
            api.handle(&post("/api/v1/jobs", body.clone()), "ip", 0)
                .status,
            401
        );
        assert_eq!(
            api.handle(
                &with_key(post("/api/v1/jobs", body), "sco_bad_invalid_secret"),
                "ip",
                0
            )
            .status,
            401
        );

        let (forbidden_api, key) = api_with_developer();
        assert_eq!(
            forbidden_api
                .handle(&with_key(get("/api/v1/keys"), &key), "ip", 0)
                .status,
            403
        );

        let value = metrics_snapshot(&api);
        assert_eq!(value["data"]["auth_failures"]["missing_key"], 1);
        assert_eq!(value["data"]["auth_failures"]["invalid_key"], 1);
        assert_eq!(value["data"]["auth_failures"]["insufficient_permission"], 0);

        let forbidden_value = metrics_snapshot(&forbidden_api);
        assert_eq!(
            forbidden_value["data"]["auth_failures"]["insufficient_permission"],
            1
        );

        let text = String::from_utf8(api.handle(&get(METRICS_PATH), "ip", 0).body).unwrap();
        assert!(text.contains("\nobservatory_api_auth_failures_missing_key_total 1\n"));
        assert!(text.contains("\nobservatory_api_auth_failures_invalid_key_total 1\n"));
        assert!(!text.contains("sco_bad_invalid_secret"));
    }

    #[test]
    fn rate_limit_rejections_increment_reason_counters() {
        let config = PlatformConfig {
            require_auth: false,
            rate_limit: observatory_platform::RateLimitConfig {
                limit: 1,
                window_secs: 60,
            },
            route_limits: BTreeMap::from([(
                METRICS_PATH.to_string(),
                observatory_platform::RateLimitConfig {
                    limit: 100,
                    window_secs: 60,
                },
            )]),
            ..PlatformConfig::default()
        };
        let api = Api::new(config);
        assert_eq!(api.handle(&get("/api/v1/health"), "ip", 0).status, 200);
        assert_eq!(api.handle(&get("/api/v1/health"), "ip", 0).status, 429);

        let value = metrics_snapshot(&api);
        assert_eq!(value["data"]["rate_limited_total"], 1);
        assert_eq!(value["data"]["rate_limit_rejections"]["window_exceeded"], 1);

        let text = String::from_utf8(api.handle(&get(METRICS_PATH), "ip", 0).body).unwrap();
        assert!(text.contains("\nobservatory_api_rate_limit_rejections_window_exceeded_total 1\n"));
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

    fn api_with_admin() -> (Api, String) {
        let api = Api::new(PlatformConfig::default());
        let key = api.generate_key(Role::Admin, "admin").unwrap();
        (api, key)
    }

    fn delete(path: &str) -> Request {
        Request {
            method: "DELETE".to_string(),
            path: path.to_string(),
            query: None,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn key_management_requires_the_manage_keys_permission() {
        let api = Api::new(PlatformConfig::default());
        let viewer = api.generate_key(Role::Viewer, "readonly").unwrap();
        let developer = api.generate_key(Role::Developer, "dev").unwrap();

        let create = post(
            "/api/v1/keys",
            serde_json::json!({ "role": "viewer", "label": "x" }),
        );
        assert_eq!(api.handle(&create, "ip", 0).status, 401);
        assert_eq!(api.handle(&with_key(create, &viewer), "ip", 0).status, 403);
        assert_eq!(
            api.handle(&with_key(get("/api/v1/keys"), &developer), "ip", 0)
                .status,
            403
        );
    }

    #[test]
    fn admin_can_create_list_and_revoke_keys() {
        let (api, admin) = api_with_admin();
        let create = with_key(
            post(
                "/api/v1/keys",
                serde_json::json!({ "role": "developer", "label": "ci" }),
            ),
            &admin,
        );
        let response = api.handle(&create, "ip", 0);
        assert_eq!(response.status, 201);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let data = &body["data"];
        let plaintext = data["plaintext"].as_str().unwrap().to_string();
        let id = data["id"].as_str().unwrap().to_string();
        assert!(plaintext.starts_with("sco_"));

        let list = api.handle(&with_key(get("/api/v1/keys"), &admin), "ip", 0);
        assert_eq!(list.status, 200);
        let listed = String::from_utf8(list.body).unwrap();
        assert!(listed.contains(&id));
        assert!(
            !listed.contains(&plaintext),
            "listing must never leak plaintext"
        );
        assert!(
            !listed.contains("\"hash\""),
            "listing must never leak hashes"
        );
        assert!(!listed.contains("\"plaintext\""));

        let analysis = with_key(
            post(
                "/api/v1/contracts/inspect",
                serde_json::json!({ "wasm_base64": contract() }),
            ),
            &plaintext,
        );
        assert_eq!(api.handle(&analysis, "ip", 0).status, 200);

        let revoke = with_key(delete(&format!("/api/v1/keys/{id}")), &admin);
        assert_eq!(api.handle(&revoke, "ip", 0).status, 200);
        assert_eq!(api.handle(&analysis, "ip", 0).status, 401);

        let missing = with_key(delete("/api/v1/keys/does-not-exist"), &admin);
        assert_eq!(api.handle(&missing, "ip", 0).status, 404);
    }

    #[test]
    fn admin_can_rotate_a_key_immediately() {
        let (api, admin) = api_with_admin();
        let created = api.handle(
            &with_key(
                post(
                    "/api/v1/keys",
                    serde_json::json!({ "role": "developer", "label": "ci" }),
                ),
                &admin,
            ),
            "ip",
            0,
        );
        let created_body: Value = serde_json::from_slice(&created.body).unwrap();
        let old_plaintext = created_body["data"]["plaintext"]
            .as_str()
            .unwrap()
            .to_string();
        let id = created_body["data"]["id"].as_str().unwrap().to_string();

        let response = api.handle(
            &with_key(
                post(
                    &format!("/api/v1/keys/{id}/rotate"),
                    serde_json::json!({ "confirm": true }),
                ),
                &admin,
            ),
            "ip",
            10,
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let data = &body["data"];
        let new_plaintext = data["plaintext"].as_str().unwrap().to_string();
        assert_ne!(new_plaintext, old_plaintext);
        assert_eq!(data["old_id"], id);
        assert_eq!(data["role"], "developer");
        assert_eq!(data["old_key_revoked_at"], 10);
        assert!(data["grace_period_secs"].is_null());

        let analysis = || {
            post(
                "/api/v1/contracts/inspect",
                serde_json::json!({ "wasm_base64": contract() }),
            )
        };
        assert_eq!(
            api.handle(&with_key(analysis(), &new_plaintext), "ip", 11)
                .status,
            200
        );
        assert_eq!(
            api.handle(&with_key(analysis(), &old_plaintext), "ip", 11)
                .status,
            401
        );
        assert!(api
            .audit_events()
            .iter()
            .any(|event| { event.action == "key.rotate" && event.outcome == "success" }));
    }

    #[test]
    fn rotation_grace_period_keeps_the_old_key_valid_until_expiry() {
        let (api, admin) = api_with_admin();
        let created = api.handle(
            &with_key(
                post(
                    "/api/v1/keys",
                    serde_json::json!({ "role": "developer", "label": "ci" }),
                ),
                &admin,
            ),
            "ip",
            0,
        );
        let created_body: Value = serde_json::from_slice(&created.body).unwrap();
        let old_plaintext = created_body["data"]["plaintext"]
            .as_str()
            .unwrap()
            .to_string();
        let id = created_body["data"]["id"].as_str().unwrap().to_string();

        let response = api.handle(
            &with_key(
                post(
                    &format!("/api/v1/keys/{id}/rotate"),
                    serde_json::json!({ "confirm": true, "grace_period_secs": 60 }),
                ),
                &admin,
            ),
            "ip",
            100,
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let new_plaintext = body["data"]["plaintext"].as_str().unwrap().to_string();
        assert_eq!(body["data"]["grace_period_secs"], 60);
        assert_eq!(body["data"]["old_key_revoked_at"], 160);

        let analysis = || {
            post(
                "/api/v1/contracts/inspect",
                serde_json::json!({ "wasm_base64": contract() }),
            )
        };
        assert_eq!(
            api.handle(&with_key(analysis(), &old_plaintext), "ip", 101)
                .status,
            200
        );
        assert_eq!(
            api.handle(&with_key(analysis(), &new_plaintext), "ip", 101)
                .status,
            200
        );
        assert_eq!(
            api.handle(&with_key(analysis(), &old_plaintext), "ip", 159)
                .status,
            200
        );
        assert_eq!(
            api.handle(&with_key(analysis(), &old_plaintext), "ip", 160)
                .status,
            401
        );
        assert_eq!(
            api.handle(&with_key(analysis(), &new_plaintext), "ip", 160)
                .status,
            200
        );
        assert!(api
            .audit_events()
            .iter()
            .any(|event| { event.action == "key.revoke" && event.outcome == "grace_expired" }));
    }

    #[test]
    fn rotation_rejects_unconfirmed_and_unknown_requests() {
        let (api, admin) = api_with_admin();
        let unconfirmed = with_key(
            post(
                "/api/v1/keys/missing/rotate",
                serde_json::json!({ "confirm": false }),
            ),
            &admin,
        );
        assert_eq!(api.handle(&unconfirmed, "ip", 0).status, 400);

        let unknown = with_key(
            post(
                "/api/v1/keys/missing/rotate",
                serde_json::json!({ "confirm": true }),
            ),
            &admin,
        );
        assert_eq!(api.handle(&unknown, "ip", 0).status, 404);
    }

    #[test]
    fn key_creation_rejects_an_unknown_role() {
        let (api, admin) = api_with_admin();
        let create = with_key(
            post(
                "/api/v1/keys",
                serde_json::json!({ "role": "superuser", "label": "x" }),
            ),
            &admin,
        );
        assert_eq!(api.handle(&create, "ip", 0).status, 400);
    }

    fn create_scoped_key(api: &Api, admin: &str, role: &str, scopes: Value) -> Response {
        api.handle(
            &with_key(
                post(
                    "/api/v1/keys",
                    serde_json::json!({ "role": role, "label": "scoped", "scopes": scopes }),
                ),
                admin,
            ),
            "ip",
            0,
        )
    }

    #[test]
    fn scoped_keys_cannot_exceed_their_scopes() {
        let (api, admin) = api_with_admin();
        let response = create_scoped_key(
            &api,
            &admin,
            "developer",
            serde_json::json!(["read_version"]),
        );
        assert_eq!(response.status, 201);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["data"]["scopes"], serde_json::json!(["read_version"]));
        let scoped = body["data"]["plaintext"].as_str().unwrap().to_string();

        let inspect = with_key(
            post(
                "/api/v1/contracts/inspect",
                serde_json::json!({ "wasm_base64": contract() }),
            ),
            &scoped,
        );
        assert_eq!(
            api.handle(&inspect, "ip", 0).status,
            403,
            "run_analysis is outside the key's scopes"
        );
    }

    #[test]
    fn scoped_keys_keep_only_their_allowed_permissions() {
        let (api, admin) = api_with_admin();
        let response = create_scoped_key(
            &api,
            &admin,
            "developer",
            serde_json::json!(["run_analysis"]),
        );
        assert_eq!(response.status, 201);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let scoped = body["data"]["plaintext"].as_str().unwrap().to_string();

        let inspect = with_key(
            post(
                "/api/v1/contracts/inspect",
                serde_json::json!({ "wasm_base64": contract() }),
            ),
            &scoped,
        );
        assert_eq!(api.handle(&inspect, "ip", 0).status, 200);
    }

    #[test]
    fn key_creation_rejects_unknown_or_excessive_scopes() {
        let (api, admin) = api_with_admin();
        assert_eq!(
            create_scoped_key(
                &api,
                &admin,
                "developer",
                serde_json::json!(["not_a_scope"])
            )
            .status,
            400
        );
        assert_eq!(
            create_scoped_key(
                &api,
                &admin,
                "developer",
                serde_json::json!(["manage_keys"])
            )
            .status,
            400,
            "a scope may not exceed its role"
        );
    }

    #[test]
    fn per_route_limits_do_not_affect_other_routes() {
        let mut route_limits = BTreeMap::new();
        route_limits.insert(
            "/api/v1/version".to_string(),
            observatory_platform::RateLimitConfig {
                limit: 1,
                window_secs: 60,
            },
        );
        let config = PlatformConfig {
            route_limits,
            rate_limit: observatory_platform::RateLimitConfig {
                limit: 10,
                window_secs: 60,
            },
            ..PlatformConfig::default()
        };
        let api = Api::new(config);

        assert_eq!(api.handle(&get("/api/v1/version"), "ip", 0).status, 200);
        let limited = api.handle(&get("/api/v1/version"), "ip", 0);
        assert_eq!(limited.status, 429);
        assert!(limited
            .headers
            .iter()
            .any(|(name, value)| name == "X-RateLimit-Limit" && value == "1"));

        let health = api.handle(&get("/api/v1/health"), "ip", 0);
        assert_eq!(health.status, 200);
        assert!(health
            .headers
            .iter()
            .any(|(name, value)| name == "X-RateLimit-Limit" && value == "10"));
    }

    fn with_accept(mut request: Request, accept: &str) -> Request {
        request
            .headers
            .insert("accept".to_string(), accept.to_string());
        request
    }

    #[test]
    fn accept_json_is_honored() {
        let api = Api::new(PlatformConfig::default());
        let response = api.handle(
            &with_accept(get("/api/v1/health"), "application/json"),
            "ip",
            0,
        );
        assert_eq!(response.status, 200);
        assert_eq!(
            header_value(&response, "Content-Type"),
            Some("application/json")
        );
    }

    #[test]
    fn missing_or_empty_accept_defaults_to_json() {
        let api = Api::new(PlatformConfig::default());
        assert_eq!(api.handle(&get("/api/v1/health"), "ip", 0).status, 200);

        let empty = api.handle(&with_accept(get("/api/v1/health"), ""), "ip", 0);
        assert_eq!(empty.status, 200);
        assert_eq!(
            header_value(&empty, "Content-Type"),
            Some("application/json")
        );
    }

    #[test]
    fn unsupported_accept_returns_406_with_the_error_envelope() {
        let api = Api::new(PlatformConfig::default());
        for accept in ["text/html", "application/xml"] {
            let response = api.handle(&with_accept(get("/api/v1/health"), accept), "ip", 0);
            assert_eq!(response.status, 406, "Accept: {accept}");
            assert_eq!(
                header_value(&response, "Content-Type"),
                Some("application/json")
            );
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body["kind"], "error");
            assert_eq!(body["code"], "not_acceptable");
        }
    }

    #[test]
    fn wildcard_accept_is_accepted() {
        let api = Api::new(PlatformConfig::default());
        for accept in ["*/*", "application/*"] {
            let response = api.handle(&with_accept(get("/api/v1/health"), accept), "ip", 0);
            assert_eq!(response.status, 200, "Accept: {accept}");
        }
    }

    #[test]
    fn keys_endpoint_paginates_deterministically() {
        let (api, admin) = api_with_admin();
        for i in 0..5 {
            let create = with_key(
                post(
                    "/api/v1/keys",
                    serde_json::json!({ "role": "viewer", "label": format!("k{i}") }),
                ),
                &admin,
            );
            assert_eq!(api.handle(&create, "ip", i).status, 201);
        }
        let mut expected: Vec<String> = api.list_keys().iter().map(|key| key.id.clone()).collect();
        expected.sort();

        let mut collected = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let query = match &cursor {
                Some(cursor) => format!("limit=2&cursor={cursor}"),
                None => "limit=2".to_string(),
            };
            let response = api.handle(
                &with_key(get_query("/api/v1/keys", &query), &admin),
                "ip",
                0,
            );
            assert_eq!(response.status, 200);
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            let page = &body["data"];
            let items = page["items"].as_array().unwrap();
            assert_eq!(page["count"].as_u64(), Some(items.len() as u64));
            collected.extend(
                items
                    .iter()
                    .map(|item| item["id"].as_str().unwrap().to_string()),
            );
            let has_more = page["has_more"].as_bool().unwrap();
            assert_eq!(page["next_cursor"].is_null(), !has_more);
            if !has_more {
                break;
            }
            cursor = Some(page["next_cursor"].as_str().unwrap().to_string());
        }
        assert_eq!(collected, expected);
    }

    #[test]
    fn jobs_list_paginates() {
        let (api, key) = api_with_developer();
        let mut created = Vec::new();
        for i in 0..3 {
            let response = api.handle(
                &with_key(
                    post(
                        "/api/v1/jobs",
                        serde_json::json!({ "kind": format!("j{i}") }),
                    ),
                    &key,
                ),
                "ip",
                i,
            );
            assert_eq!(response.status, 201);
            created.push(created_id(&response));
        }

        let mut collected = Vec::new();
        let response = api.handle(
            &with_key(get_query("/api/v1/jobs", "limit=2"), &key),
            "ip",
            0,
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["data"]["count"].as_u64(), Some(2));
        assert_eq!(body["data"]["has_more"].as_bool(), Some(true));
        collected.extend(
            body["data"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|job| job["id"].as_str().unwrap().to_string()),
        );
        let cursor = body["data"]["next_cursor"].as_str().unwrap().to_string();

        let response = api.handle(
            &with_key(
                get_query("/api/v1/jobs", &format!("limit=2&cursor={cursor}")),
                &key,
            ),
            "ip",
            0,
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["data"]["count"].as_u64(), Some(1));
        assert_eq!(body["data"]["has_more"].as_bool(), Some(false));
        assert!(body["data"]["next_cursor"].is_null());
        collected.extend(
            body["data"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|job| job["id"].as_str().unwrap().to_string()),
        );
        assert_eq!(collected, created);
    }

    #[test]
    fn webhooks_list_paginates() {
        let (api, key) = maintainer_api();
        let mut created = Vec::new();
        for i in 0..3 {
            let create = with_key(
                post(
                    "/api/v1/webhooks",
                    serde_json::json!({
                        "url": format!("https://example.com/hook{i}"),
                        "events": ["analysis_completed"],
                    }),
                ),
                &key,
            );
            let response = api.handle(&create, "ip", i);
            assert_eq!(response.status, 201);
            created.push(created_id(&response));
        }

        let mut collected = Vec::new();
        let response = api.handle(
            &with_key(get_query("/api/v1/webhooks", "limit=2"), &key),
            "ip",
            0,
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["data"]["count"].as_u64(), Some(2));
        assert_eq!(body["data"]["has_more"].as_bool(), Some(true));
        collected.extend(
            body["data"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|sub| sub["id"].as_str().unwrap().to_string()),
        );
        let cursor = body["data"]["next_cursor"].as_str().unwrap().to_string();

        let response = api.handle(
            &with_key(
                get_query("/api/v1/webhooks", &format!("limit=2&cursor={cursor}")),
                &key,
            ),
            "ip",
            0,
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["data"]["count"].as_u64(), Some(1));
        assert_eq!(body["data"]["has_more"].as_bool(), Some(false));
        assert!(body["data"]["next_cursor"].is_null());
        collected.extend(
            body["data"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|sub| sub["id"].as_str().unwrap().to_string()),
        );
        created.sort();
        assert_eq!(collected, created);
    }

    #[test]
    fn audit_events_endpoint_is_admin_only_redacted_and_paginated() {
        let (api, admin) = api_with_admin();
        let developer = api.generate_key(Role::Developer, "dev").unwrap();
        assert_eq!(
            api.handle(&with_key(get("/api/v1/audit/events"), &developer), "ip", 0)
                .status,
            403
        );
        let mut plaintexts = Vec::new();
        for i in 0..3 {
            plaintexts.push(api.generate_key(Role::Viewer, &format!("v{i}")).unwrap());
        }

        let mut seen = 0_usize;
        let mut cursor: Option<String> = None;
        loop {
            let query = match &cursor {
                Some(cursor) => format!("limit=2&cursor={cursor}"),
                None => "limit=2".to_string(),
            };
            let response = api.handle(
                &with_key(get_query("/api/v1/audit/events", &query), &admin),
                "ip",
                0,
            );
            assert_eq!(response.status, 200);
            let text = String::from_utf8_lossy(&response.body);
            assert!(
                !text.contains("sco_"),
                "the audit read path must never leak key material"
            );
            for plaintext in &plaintexts {
                assert!(!text.contains(plaintext.as_str()));
            }
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            let page = &body["data"];
            seen += page["items"].as_array().unwrap().len();
            let has_more = page["has_more"].as_bool().unwrap();
            assert_eq!(page["next_cursor"].is_null(), !has_more);
            if !has_more {
                break;
            }
            cursor = Some(page["next_cursor"].as_str().unwrap().to_string());
        }
        assert_eq!(seen, api.audit_events().len());
        assert!(seen >= 5);
    }

    #[test]
    fn list_endpoints_reject_bad_pagination_params() {
        let (api, admin) = api_with_admin();
        for path in [
            "/api/v1/jobs",
            "/api/v1/keys",
            "/api/v1/webhooks",
            "/api/v1/audit/events",
        ] {
            for query in [
                "limit=0",
                "limit=-1",
                "limit=abc",
                "limit=1001",
                "cursor=%%%",
                "cursor=abc",
            ] {
                let response = api.handle(&with_key(get_query(path, query), &admin), "ip", 0);
                assert_eq!(response.status, 400, "{path}?{query}");
            }
        }
    }

    #[test]
    fn handle_emits_a_request_span() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct SpanRecorder {
            names: Arc<Mutex<Vec<String>>>,
            next: Arc<AtomicU64>,
        }

        impl tracing::Subscriber for SpanRecorder {
            fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                self.names
                    .lock()
                    .unwrap()
                    .push(span.metadata().name().to_string());
                let next = self.next.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::span::Id::from_u64(next)
            }

            fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

            fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
            }

            fn event(&self, _event: &tracing::Event<'_>) {}

            fn enter(&self, _span: &tracing::span::Id) {}

            fn exit(&self, _span: &tracing::span::Id) {}
        }

        // A dedicated thread keeps this recording away from other tests
        // running concurrently on shared tracing dispatch state.
        let handle = std::thread::spawn(|| {
            let recorder = SpanRecorder {
                names: Arc::new(Mutex::new(Vec::new())),
                next: Arc::new(AtomicU64::new(0)),
            };
            let names = recorder.names.clone();
            tracing::subscriber::with_default(recorder, || {
                let api = Api::new(PlatformConfig::default());
                // Spans can occasionally be skipped by the scoped dispatcher
                // machinery under parallel test execution, so repeat the
                // calls a few times.
                for _ in 0..5 {
                    let _ = api.handle(&get("/api/v1/health"), "ip", 0);
                }
            });
            let recorded = names.lock().unwrap().clone();
            recorded
        });
        let names = handle.join().unwrap();
        assert!(names.iter().any(|name| name == "http_request"));
    }
}
