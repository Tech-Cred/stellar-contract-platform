//! Structured audit events for privileged and security-relevant actions (#43).
//!
//! Events are machine-readable and deliberately small: actor (the public API-key
//! id, never the secret), action, resource, outcome, request id, and timestamp.
//! The log is in-memory and bounded, so a burst of requests cannot grow it
//! without limit.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// Schema version of an audit event.
pub const AUDIT_SCHEMA_VERSION: &str = "1.0";

/// One structured audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Schema version.
    pub schema_version: String,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// Public API-key id of the actor, when authenticated.
    pub actor: Option<String>,
    /// Stable action name (for example `analysis.run`).
    pub action: String,
    /// Resource the action targeted (path, key id, job id).
    pub resource: String,
    /// Outcome: `success`, `failure`, or `denied`.
    pub outcome: String,
    /// Correlated request id, when available.
    pub request_id: Option<String>,
}

impl AuditEvent {
    /// Build an event. Callers must not pass secrets in any field.
    #[must_use]
    pub fn new(
        timestamp: u64,
        actor: Option<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        outcome: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            timestamp,
            actor,
            action: action.into(),
            resource: resource.into(),
            outcome: outcome.into(),
            request_id,
        }
    }
}

/// A bounded, in-memory audit log.
#[derive(Debug)]
pub struct AuditLog {
    capacity: usize,
    events: VecDeque<AuditEvent>,
}

impl Default for AuditLog {
    fn default() -> Self {
        AuditLog::new(AuditLog::DEFAULT_CAPACITY)
    }
}

impl AuditLog {
    /// Default maximum number of retained events.
    pub const DEFAULT_CAPACITY: usize = 1024;

    /// Create a log retaining at most `capacity` events.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        AuditLog {
            capacity: capacity.max(1),
            events: VecDeque::new(),
        }
    }

    /// Record an event, evicting the oldest when the log is full.
    pub fn record(&mut self, event: AuditEvent) {
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Retained events, oldest first.
    #[must_use]
    pub fn events(&self) -> &VecDeque<AuditEvent> {
        &self.events
    }

    /// Clone the retained events.
    #[must_use]
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.iter().cloned().collect()
    }

    /// Number of retained events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(action: &str) -> AuditEvent {
        AuditEvent::new(1, Some("key-1".into()), action, "/x", "success", None)
    }

    #[test]
    fn records_and_evicts_oldest() {
        let mut log = AuditLog::new(2);
        log.record(event("a"));
        log.record(event("b"));
        log.record(event("c"));
        assert_eq!(log.len(), 2);
        let actions: Vec<_> = log.snapshot().into_iter().map(|e| e.action).collect();
        assert_eq!(actions, vec!["b", "c"]);
    }

    #[test]
    fn events_are_machine_readable_and_carry_no_secret_field() {
        let value = serde_json::to_value(event("key.create")).unwrap();
        assert_eq!(value["schema_version"], AUDIT_SCHEMA_VERSION);
        assert_eq!(value["action"], "key.create");
        assert!(value.get("secret").is_none());
        assert!(value.get("plaintext").is_none());
    }
}
