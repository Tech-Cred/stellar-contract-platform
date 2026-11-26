//! Application/service layer and platform concerns for the Observatory.
//!
//! This crate introduces no analysis logic of its own. [`service::Observatory`]
//! composes the contract-intelligence crates into coarse application services,
//! and the remaining modules provide authentication, authorization, and rate
//! limiting that a transport layer (for example `observatory-api`) can apply.
//!
//! Keeping these concerns out of the intelligence crates preserves the
//! dependency direction: the platform depends on the engine, never the reverse.

pub mod audit;
pub mod auth;
pub mod config;
pub mod jobs;
pub mod policy;
pub mod project;
pub mod ratelimit;
pub mod rbac;
pub mod security;
pub mod service;
pub mod store;
pub mod webhook;
pub mod webhook_delivery;

pub use audit::{AuditEvent, AuditLog};
pub use auth::{ApiKeyRecord, ApiKeyStore, KeyRotation, KeyStore, Principal};
pub use config::{AuditConfig, CorsConfig, NetworkProfile, PlatformConfig};
pub use jobs::{Job, JobQueue, JobState};
pub use observatory_compat::CompatibilityPolicy;
pub use policy::{load_policy, parse_policy};
pub use project::{ConfigFormat, ProjectConfig};
pub use ratelimit::{RateLimitConfig, RateLimitDecision, RateLimiter};
pub use rbac::{authorize, authorize_with_scopes, validate_scopes, Permission, Role};
pub use security::{
    AuthFailureReason, RateLimitReason, SecurityMetrics, SecurityMetricsSnapshot,
    AUTH_FAILURE_REASONS, RATE_LIMIT_REASONS,
};
pub use service::Observatory;
pub use store::FileKeyStore;
pub use webhook::{
    validate_webhook_url, WebhookCreated, WebhookEvent, WebhookStore, WebhookSubscription,
};
pub use webhook_delivery::{
    deliver, sign, verify, Clock, DeliveryOutcome, DeliveryStatus, HttpTransport, Sleeper,
    SystemClock, ThreadSleeper, WebhookConfig, WebhookRegistration, WebhookTransport,
};
