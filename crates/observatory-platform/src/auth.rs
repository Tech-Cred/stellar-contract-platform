//! API-key authentication.
//!
//! Keys are generated with OS randomness and stored only as SHA-256 hashes. The
//! plaintext key is returned exactly once, at creation. The record never
//! serializes the hash, so a leaked record cannot be replayed.

use std::collections::BTreeMap;

use observatory_core::error::redact_secrets;
use observatory_core::hash::sha256_hex;
use observatory_core::{ObservatoryError, Result};
use serde::Serialize;

use crate::rbac::{Permission, Role};

/// Prefix identifying an Observatory API key.
pub const KEY_PREFIX: &str = "sco";

/// A stored API-key record. The secret hash is never serialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKeyRecord {
    /// Public key identifier (also present in the plaintext key).
    pub id: String,
    /// SHA-256 of the secret. Excluded from serialization.
    #[serde(skip)]
    pub hash: String,
    /// The role granted to the key.
    pub role: Role,
    /// Optional subset of the role's permissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<Permission>>,
    /// A human label.
    pub label: String,
    /// Whether the key has been revoked.
    pub revoked: bool,
}

/// The authenticated identity behind a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Principal {
    /// The API-key id.
    pub key_id: String,
    /// The granted role.
    pub role: Role,
    /// Optional subset of the role's permissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<Permission>>,
}

/// Metadata describing one completed key rotation.
///
/// The new plaintext is returned separately and is never stored in this
/// struct, so debug logs and serialized responses cannot leak it by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyRotation {
    /// The id of the key being replaced.
    pub old_id: String,
    /// Metadata for the freshly generated replacement key.
    pub new_record: ApiKeyRecord,
    /// Seconds from the Unix epoch when the old key is revoked. Equal to the
    /// rotation time when no grace period was requested.
    pub revoke_at: u64,
    /// The requested grace period, or `None` for immediate revocation.
    pub grace_period_secs: Option<u64>,
}

/// A pluggable API-key store.
///
/// Implementations must never store or log the plaintext key. The in-memory
/// backend is the default for tests; [`crate::store::FileKeyStore`] persists
/// only metadata and hashes so keys survive a restart.
pub trait KeyStore: Send + Sync {
    /// Generate a new key, returning the plaintext exactly once.
    fn generate(
        &mut self,
        role: Role,
        label: &str,
        scopes: Option<Vec<Permission>>,
    ) -> Result<(String, ApiKeyRecord)>;
    /// Insert a record from a pre-computed hash (fixtures/imports).
    fn insert_hashed(&mut self, id: &str, hash: &str, role: Role, label: &str) -> ApiKeyRecord;
    /// Register a key from its plaintext form.
    fn insert_plaintext(
        &mut self,
        plaintext: &str,
        role: Role,
        label: &str,
    ) -> Result<ApiKeyRecord>;
    /// Revoke a key by id.
    fn revoke(&mut self, id: &str) -> bool;
    /// Change a live key's role.
    fn set_role(&mut self, id: &str, role: Role) -> bool;
    /// Create a fresh replacement for `id` with the same role.
    ///
    /// `label` and `scopes` override the old key's metadata when supplied.
    /// With no grace period the old key is revoked immediately; otherwise it
    /// stays valid until `revoke_at`. Returns `None` when the id is unknown or
    /// already revoked.
    fn rotate(
        &mut self,
        id: &str,
        label: Option<&str>,
        scopes: Option<Vec<Permission>>,
        grace_period_secs: Option<u64>,
        now_secs: u64,
    ) -> Result<Option<(String, KeyRotation)>>;
    /// Revoke keys whose rotation grace period has elapsed.
    ///
    /// Returns the revoked ids so callers can audit the transition.
    fn revoke_expired(&mut self, now_secs: u64) -> Vec<String>;
    /// Authenticate a presented key.
    fn authenticate(&self, provided: &str) -> Option<Principal>;
    /// List key metadata, sorted by id. Records never serialize the hash.
    fn list(&self) -> Vec<ApiKeyRecord>;
    /// Number of stored keys.
    fn len(&self) -> usize;
    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An in-memory API-key store.
#[derive(Debug, Default)]
pub struct ApiKeyStore {
    keys: BTreeMap<String, ApiKeyRecord>,
    // Old key id -> epoch seconds at which rotation revokes it. `pub(crate)`
    // lets the file-backed store persist pending grace periods.
    pub(crate) pending_revocations: BTreeMap<String, u64>,
}

impl ApiKeyStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        ApiKeyStore::default()
    }

    /// Generate a new key for `role`. Returns `(plaintext, record)`.
    ///
    /// The plaintext is shown once and never stored. `scopes` narrows the role
    /// when present; callers are expected to validate it against the role first.
    pub fn generate(
        &mut self,
        role: Role,
        label: &str,
        scopes: Option<Vec<Permission>>,
    ) -> Result<(String, ApiKeyRecord)> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret)
            .map_err(|error| ObservatoryError::internal(format!("randomness failure: {error}")))?;
        let secret_hex = hex::encode(secret);
        let id = sha256_hex(format!("{label}:{secret_hex}").as_bytes())[..16].to_string();
        let plaintext = format!("{KEY_PREFIX}_{id}_{secret_hex}");
        let record = ApiKeyRecord {
            id: id.clone(),
            hash: sha256_hex(secret_hex.as_bytes()),
            role,
            scopes,
            label: label.to_string(),
            revoked: false,
        };
        self.keys.insert(id, record.clone());
        Ok((plaintext, record))
    }

    /// Insert a record directly (for fixtures and imports).
    pub fn insert_hashed(
        &mut self,
        id: impl Into<String>,
        hash: impl Into<String>,
        role: Role,
        label: &str,
    ) -> ApiKeyRecord {
        let record = ApiKeyRecord {
            id: id.into(),
            hash: hash.into(),
            role,
            scopes: None,
            label: label.to_string(),
            revoked: false,
        };
        self.keys.insert(record.id.clone(), record.clone());
        record
    }

    /// Insert a complete record, including its revocation state.
    ///
    /// Used when loading a persistent backend. The hash is expected to be an
    /// already-computed SHA-256 digest.
    pub fn insert_record(&mut self, record: ApiKeyRecord) -> ApiKeyRecord {
        self.keys.insert(record.id.clone(), record.clone());
        record
    }

    /// Register a key from its plaintext form (`sco_<id>_<secret>`).
    ///
    /// Only the hash is stored. This is how a server is configured with keys
    /// without a persistence layer.
    pub fn insert_plaintext(
        &mut self,
        plaintext: &str,
        role: Role,
        label: &str,
    ) -> Result<ApiKeyRecord> {
        let redacted = redact_secrets(plaintext.trim());
        let mut parts = plaintext.trim().splitn(3, '_');
        if parts.next() != Some(KEY_PREFIX) {
            return Err(ObservatoryError::invalid(format!(
                "API key `{redacted}` must start with `sco_`"
            )));
        }
        let id = parts
            .next()
            .ok_or_else(|| ObservatoryError::invalid("API key is missing its id"))?
            .to_string();
        let secret = parts
            .next()
            .ok_or_else(|| ObservatoryError::invalid("API key is missing its secret"))?;
        let record = ApiKeyRecord {
            id: id.clone(),
            hash: sha256_hex(secret.as_bytes()),
            role,
            scopes: None,
            label: label.to_string(),
            revoked: false,
        };
        self.keys.insert(id, record.clone());
        Ok(record)
    }

    /// Change a live key's role. Returns whether the key was updated.
    pub fn set_role(&mut self, id: &str, role: Role) -> bool {
        match self.keys.get_mut(id) {
            Some(record) if !record.revoked => {
                record.role = role;
                true
            }
            _ => false,
        }
    }

    /// Revoke a key by id. Returns whether a key was revoked.
    pub fn revoke(&mut self, id: &str) -> bool {
        match self.keys.get_mut(id) {
            Some(record) => {
                record.revoked = true;
                true
            }
            None => false,
        }
    }

    /// Create a fresh replacement for `id`.
    ///
    /// The old key is revoked immediately unless a grace period is supplied.
    /// The replacement inherits the old role, label, and scopes unless they are
    /// explicitly overridden. The new plaintext is returned exactly once.
    pub fn rotate(
        &mut self,
        id: &str,
        label: Option<&str>,
        scopes: Option<Vec<Permission>>,
        grace_period_secs: Option<u64>,
        now_secs: u64,
    ) -> Result<Option<(String, KeyRotation)>> {
        let (role, effective_label, effective_scopes, old_hash) = {
            let Some(record) = self.keys.get(id) else {
                return Ok(None);
            };
            if record.revoked {
                return Ok(None);
            }
            let role = record.role;
            let effective_label = label.unwrap_or(&record.label).to_string();
            let effective_scopes = scopes.or_else(|| record.scopes.clone());
            let old_hash = record.hash.clone();
            (role, effective_label, effective_scopes, old_hash)
        };

        let (plaintext, new_record) = self.generate(role, &effective_label, effective_scopes)?;
        if new_record.hash == old_hash {
            self.keys.remove(&new_record.id);
            return Err(ObservatoryError::internal(
                "rotation produced a repeated secret",
            ));
        }

        let revoke_at = grace_period_secs.map_or(now_secs, |grace| now_secs.saturating_add(grace));
        let rotation = KeyRotation {
            old_id: id.to_string(),
            new_record: new_record.clone(),
            revoke_at,
            grace_period_secs,
        };
        if revoke_at <= now_secs {
            self.revoke(id);
        } else {
            self.pending_revocations.insert(id.to_string(), revoke_at);
        }
        Ok(Some((plaintext, rotation)))
    }

    /// Revoke keys whose rotation grace period has elapsed.
    pub fn revoke_expired(&mut self, now_secs: u64) -> Vec<String> {
        let due: Vec<String> = self
            .pending_revocations
            .iter()
            .filter(|(_, revoke_at)| **revoke_at <= now_secs)
            .map(|(id, _)| id.clone())
            .collect();
        let mut revoked = Vec::new();
        for id in due {
            self.pending_revocations.remove(&id);
            if let Some(record) = self.keys.get_mut(&id) {
                if !record.revoked {
                    record.revoked = true;
                    revoked.push(id);
                }
            }
        }
        revoked
    }

    /// Key metadata, sorted by id.
    ///
    /// The returned records carry the hash in memory, but [`ApiKeyRecord`]
    /// skips it during serialization.
    #[must_use]
    pub fn list(&self) -> Vec<ApiKeyRecord> {
        self.keys.values().cloned().collect()
    }

    /// The number of stored keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Authenticate a presented key, returning the principal on success.
    #[must_use]
    pub fn authenticate(&self, provided: &str) -> Option<Principal> {
        let mut parts = provided.trim().splitn(3, '_');
        if parts.next()? != KEY_PREFIX {
            return None;
        }
        let id = parts.next()?;
        let secret = parts.next()?;
        let record = self.keys.get(id)?;
        if record.revoked {
            return None;
        }
        if sha256_hex(secret.as_bytes()) != record.hash {
            return None;
        }
        Some(Principal {
            key_id: record.id.clone(),
            role: record.role,
            scopes: record.scopes.clone(),
        })
    }
}

impl KeyStore for ApiKeyStore {
    fn generate(
        &mut self,
        role: Role,
        label: &str,
        scopes: Option<Vec<Permission>>,
    ) -> Result<(String, ApiKeyRecord)> {
        ApiKeyStore::generate(self, role, label, scopes)
    }

    fn insert_hashed(&mut self, id: &str, hash: &str, role: Role, label: &str) -> ApiKeyRecord {
        ApiKeyStore::insert_hashed(self, id, hash, role, label)
    }

    fn insert_plaintext(
        &mut self,
        plaintext: &str,
        role: Role,
        label: &str,
    ) -> Result<ApiKeyRecord> {
        ApiKeyStore::insert_plaintext(self, plaintext, role, label)
    }

    fn revoke(&mut self, id: &str) -> bool {
        ApiKeyStore::revoke(self, id)
    }

    fn set_role(&mut self, id: &str, role: Role) -> bool {
        ApiKeyStore::set_role(self, id, role)
    }

    fn rotate(
        &mut self,
        id: &str,
        label: Option<&str>,
        scopes: Option<Vec<Permission>>,
        grace_period_secs: Option<u64>,
        now_secs: u64,
    ) -> Result<Option<(String, KeyRotation)>> {
        ApiKeyStore::rotate(self, id, label, scopes, grace_period_secs, now_secs)
    }

    fn revoke_expired(&mut self, now_secs: u64) -> Vec<String> {
        ApiKeyStore::revoke_expired(self, now_secs)
    }

    fn authenticate(&self, provided: &str) -> Option<Principal> {
        ApiKeyStore::authenticate(self, provided)
    }

    fn list(&self) -> Vec<ApiKeyRecord> {
        ApiKeyStore::list(self)
    }

    fn len(&self) -> usize {
        ApiKeyStore::len(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_authenticate() {
        let mut store = ApiKeyStore::new();
        let (plaintext, record) = store.generate(Role::Developer, "ci", None).unwrap();
        assert!(plaintext.starts_with("sco_"));
        let principal = store.authenticate(&plaintext).unwrap();
        assert_eq!(principal.key_id, record.id);
        assert_eq!(principal.role, Role::Developer);
    }

    #[test]
    fn wrong_secret_and_prefix_fail() {
        let mut store = ApiKeyStore::new();
        let (_, record) = store.generate(Role::Viewer, "x", None).unwrap();
        assert!(store.authenticate("sco_wrong_deadbeef").is_none());
        assert!(store.authenticate("nope").is_none());
        let forged = format!("sco_{}_00", record.id);
        assert!(store.authenticate(&forged).is_none());
    }

    #[test]
    fn revoked_keys_fail() {
        let mut store = ApiKeyStore::new();
        let (plaintext, record) = store.generate(Role::Admin, "ops", None).unwrap();
        assert!(store.revoke(&record.id));
        assert!(store.authenticate(&plaintext).is_none());
        assert!(!store.revoke("missing"));
    }

    #[test]
    fn rotation_creates_a_fresh_key_and_revokes_the_old_one() {
        let mut store = ApiKeyStore::new();
        let (old_plaintext, old_record) = store
            .generate(Role::Developer, "ci", Some(vec![Permission::RunAnalysis]))
            .unwrap();
        let (new_plaintext, rotation) = store
            .rotate(&old_record.id, None, None, None, 10)
            .unwrap()
            .expect("rotation succeeds");

        assert_ne!(old_plaintext, new_plaintext);
        assert_ne!(old_record.hash, rotation.new_record.hash);
        assert_eq!(rotation.old_id, old_record.id);
        assert_eq!(rotation.revoke_at, 10);
        assert_eq!(rotation.grace_period_secs, None);
        assert_eq!(rotation.new_record.role, Role::Developer);
        assert_eq!(rotation.new_record.scopes, old_record.scopes);
        assert_eq!(rotation.new_record.label, old_record.label);
        assert_eq!(
            store.authenticate(&new_plaintext).unwrap().role,
            Role::Developer
        );
        assert!(store.authenticate(&old_plaintext).is_none());
        assert!(store
            .rotate(&old_record.id, None, None, None, 10)
            .unwrap()
            .is_none());
    }

    #[test]
    fn rotation_grace_period_delays_revocation_until_expiry() {
        let mut store = ApiKeyStore::new();
        let (old_plaintext, old_record) = store.generate(Role::Admin, "ops", None).unwrap();
        let (new_plaintext, rotation) = store
            .rotate(&old_record.id, None, None, Some(60), 100)
            .unwrap()
            .expect("rotation succeeds");

        assert_eq!(rotation.revoke_at, 160);
        assert_eq!(rotation.grace_period_secs, Some(60));
        assert!(store.authenticate(&old_plaintext).is_some());
        assert!(store.authenticate(&new_plaintext).is_some());
        assert!(store.revoke_expired(159).is_empty());
        assert!(store.authenticate(&old_plaintext).is_some());
        assert_eq!(store.revoke_expired(160), vec![old_record.id]);
        assert!(store.authenticate(&old_plaintext).is_none());
        assert!(store.authenticate(&new_plaintext).is_some());
        assert!(store.revoke_expired(160).is_empty());
    }

    #[test]
    fn rotation_can_override_label_and_scopes() {
        let mut store = ApiKeyStore::new();
        let (_, old_record) = store.generate(Role::Developer, "ci", None).unwrap();
        let (_, rotation) = store
            .rotate(
                &old_record.id,
                Some("ci-rotated"),
                Some(vec![Permission::ReadVersion]),
                None,
                0,
            )
            .unwrap()
            .expect("rotation succeeds");

        assert_eq!(rotation.new_record.label, "ci-rotated");
        assert_eq!(
            rotation.new_record.scopes,
            Some(vec![Permission::ReadVersion])
        );
    }

    #[test]
    fn records_never_serialize_the_hash() {
        let mut store = ApiKeyStore::new();
        let (_, record) = store.generate(Role::Viewer, "x", None).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains(&record.hash));
        assert!(!json.contains("hash"));
    }

    #[test]
    fn auth_errors_and_logs_never_echo_the_presented_key() {
        let presented = "https://user:pass@example.org/rpc?api_key=SECRET";
        let mut store = ApiKeyStore::new();
        let rendered = store
            .insert_plaintext(presented, Role::Viewer, "bad")
            .unwrap_err()
            .to_string();
        for secret in ["user", "pass", "SECRET", presented] {
            assert!(!rendered.contains(secret), "{rendered}");
        }

        let (plaintext, record) = store.generate(Role::Viewer, "ci", None).unwrap();
        assert!(!format!("{record:?}").contains(&plaintext));
        assert!(!format!("{:?}", store.authenticate(&plaintext)).contains(&plaintext));
    }

    #[test]
    fn scopes_survive_authentication() {
        let mut store = ApiKeyStore::new();
        let (plaintext, record) = store
            .generate(Role::Developer, "ci", Some(vec![Permission::RunAnalysis]))
            .unwrap();
        let principal = store.authenticate(&plaintext).unwrap();
        assert_eq!(principal.role, record.role);
        assert_eq!(principal.scopes, Some(vec![Permission::RunAnalysis]));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("run_analysis"));
    }
}
