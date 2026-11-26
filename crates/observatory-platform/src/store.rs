//! Persistent API-key storage.
//!
//! The in-memory [`KeyStore`] is the default for tests.
//! [`FileKeyStore`] adds durability without changing the authentication model:
//! it stores only the id, hash, role, label, and revocation state. The plaintext
//! key is returned once at creation and is never written to disk.
//!
//! The file is JSON with an explicit version. Writes go to a temporary file and
//! are renamed into place, so a crash cannot leave a half-written store.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use observatory_core::{ObservatoryError, Result};
use serde::{Deserialize, Serialize};

use crate::auth::{ApiKeyRecord, ApiKeyStore, KeyRotation, KeyStore, Principal};
use crate::rbac::{Permission, Role};

/// On-disk format version.
pub const STORE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct PersistedStore {
    version: u32,
    keys: Vec<PersistedKey>,
    #[serde(default)]
    pending_revocations: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedKey {
    id: String,
    hash: String,
    role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<Permission>>,
    label: String,
    revoked: bool,
}

impl From<ApiKeyRecord> for PersistedKey {
    fn from(record: ApiKeyRecord) -> Self {
        PersistedKey {
            id: record.id,
            hash: record.hash,
            role: record.role,
            scopes: record.scopes,
            label: record.label,
            revoked: record.revoked,
        }
    }
}

impl From<PersistedKey> for ApiKeyRecord {
    fn from(key: PersistedKey) -> Self {
        ApiKeyRecord {
            id: key.id,
            hash: key.hash,
            role: key.role,
            scopes: key.scopes,
            label: key.label,
            revoked: key.revoked,
        }
    }
}

/// A file-backed API-key store.
///
/// The default backend for tests stays in memory. Use this backend when keys
/// must survive a process restart.
#[derive(Debug)]
pub struct FileKeyStore {
    path: PathBuf,
    inner: ApiKeyStore,
}

impl FileKeyStore {
    /// Open (or create) a store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let inner = if path.exists() {
            let text = fs::read_to_string(&path).map_err(|error| {
                ObservatoryError::internal(format!(
                    "cannot read key store {}: {error}",
                    path.display()
                ))
            })?;
            let persisted: PersistedStore = serde_json::from_str(&text).map_err(|error| {
                ObservatoryError::invalid(format!("invalid key store {}: {error}", path.display()))
            })?;
            if persisted.version != STORE_VERSION {
                return Err(ObservatoryError::invalid(format!(
                    "unsupported key store version {} (expected {STORE_VERSION})",
                    persisted.version
                )));
            }
            let mut store = ApiKeyStore::new();
            for key in persisted.keys {
                store.insert_record(key.into());
            }
            store.pending_revocations = persisted.pending_revocations;
            store
        } else {
            ApiKeyStore::new()
        };
        Ok(FileKeyStore { path, inner })
    }

    /// The backing file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    ObservatoryError::internal(format!(
                        "cannot create key store directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let document = PersistedStore {
            version: STORE_VERSION,
            keys: self
                .inner
                .list()
                .into_iter()
                .map(PersistedKey::from)
                .collect(),
            pending_revocations: self.inner.pending_revocations.clone(),
        };
        let text = serde_json::to_string_pretty(&document).map_err(|error| {
            ObservatoryError::internal(format!("cannot encode key store: {error}"))
        })?;
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&temporary, text).map_err(|error| {
            ObservatoryError::internal(format!(
                "cannot write key store {}: {error}",
                temporary.display()
            ))
        })?;
        fs::rename(&temporary, &self.path).map_err(|error| {
            let _ = fs::remove_file(&temporary);
            ObservatoryError::internal(format!(
                "cannot replace key store {}: {error}",
                self.path.display()
            ))
        })
    }
}

impl KeyStore for FileKeyStore {
    fn generate(
        &mut self,
        role: Role,
        label: &str,
        scopes: Option<Vec<Permission>>,
    ) -> Result<(String, ApiKeyRecord)> {
        let result = self.inner.generate(role, label, scopes)?;
        self.persist()?;
        Ok(result)
    }

    fn insert_hashed(&mut self, id: &str, hash: &str, role: Role, label: &str) -> ApiKeyRecord {
        let record = self.inner.insert_hashed(id, hash, role, label);
        let _ = self.persist();
        record
    }

    fn insert_plaintext(
        &mut self,
        plaintext: &str,
        role: Role,
        label: &str,
    ) -> Result<ApiKeyRecord> {
        let record = self.inner.insert_plaintext(plaintext, role, label)?;
        self.persist()?;
        Ok(record)
    }

    fn revoke(&mut self, id: &str) -> bool {
        let revoked = self.inner.revoke(id);
        if revoked {
            let _ = self.persist();
        }
        revoked
    }

    fn set_role(&mut self, id: &str, role: Role) -> bool {
        let changed = self.inner.set_role(id, role);
        if changed {
            let _ = self.persist();
        }
        changed
    }

    fn rotate(
        &mut self,
        id: &str,
        label: Option<&str>,
        scopes: Option<Vec<Permission>>,
        grace_period_secs: Option<u64>,
        now_secs: u64,
    ) -> Result<Option<(String, KeyRotation)>> {
        let rotated = self
            .inner
            .rotate(id, label, scopes, grace_period_secs, now_secs)?;
        if rotated.is_some() {
            self.persist()?;
        }
        Ok(rotated)
    }

    fn revoke_expired(&mut self, now_secs: u64) -> Vec<String> {
        let revoked = self.inner.revoke_expired(now_secs);
        if !revoked.is_empty() {
            let _ = self.persist();
        }
        revoked
    }

    fn authenticate(&self, provided: &str) -> Option<Principal> {
        self.inner.authenticate(provided)
    }

    fn list(&self) -> Vec<ApiKeyRecord> {
        self.inner.list()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "observatory-keys-{}-{unique}/keys.json",
            std::process::id()
        ))
    }

    #[test]
    fn keys_survive_a_reopen_without_storing_plaintext() {
        let path = temp_path();
        let (plaintext, record) = {
            let mut store = FileKeyStore::open(&path).unwrap();
            let (plaintext, record) = store.generate(Role::Admin, "ops", None).unwrap();
            store.insert_hashed("fixture", "deadbeef", Role::Viewer, "fixture");
            (plaintext, record)
        };

        let text = fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(&plaintext),
            "plaintext must never be persisted"
        );
        assert!(text.contains(&record.hash), "the hash is persisted");

        let reopened = FileKeyStore::open(&path).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.authenticate(&plaintext).unwrap().role, Role::Admin);
        let metadata = reopened.list();
        let serialized = serde_json::to_string(&metadata).unwrap();
        assert!(!serialized.contains("deadbeef"));
        assert!(!serialized.contains(&record.hash));

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn revoked_keys_stay_revoked_after_a_reopen() {
        let path = temp_path();
        let (plaintext, id) = {
            let mut store = FileKeyStore::open(&path).unwrap();
            let (plaintext, record) = store.generate(Role::Developer, "ci", None).unwrap();
            assert!(store.revoke(&record.id));
            (plaintext, record.id)
        };

        let reopened = FileKeyStore::open(&path).unwrap();
        assert!(reopened.authenticate(&plaintext).is_none());
        assert!(reopened
            .list()
            .iter()
            .any(|key| key.id == id && key.revoked));

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn scopes_survive_a_reopen() {
        let path = temp_path();
        let (plaintext, record) = {
            let mut store = FileKeyStore::open(&path).unwrap();
            store
                .generate(
                    Role::Developer,
                    "scoped",
                    Some(vec![crate::rbac::Permission::ReadVersion]),
                )
                .unwrap()
        };
        let reopened = FileKeyStore::open(&path).unwrap();
        let principal = reopened.authenticate(&plaintext).unwrap();
        assert_eq!(
            principal.scopes,
            Some(vec![crate::rbac::Permission::ReadVersion])
        );
        assert!(reopened
            .list()
            .iter()
            .any(|key| key.id == record.id && key.scopes.is_some()));

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rotation_and_pending_grace_survive_a_reopen() {
        let path = temp_path();
        let (old_plaintext, old_id, new_plaintext, rotation) = {
            let mut store = FileKeyStore::open(&path).unwrap();
            let (old_plaintext, record) = store.generate(Role::Developer, "ci", None).unwrap();
            let (new_plaintext, rotation) = store
                .rotate(&record.id, None, None, Some(60), 100)
                .unwrap()
                .expect("rotation succeeds");
            (old_plaintext, record.id, new_plaintext, rotation)
        };
        assert_eq!(rotation.revoke_at, 160);

        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&old_plaintext));
        assert!(!text.contains(&new_plaintext));
        assert!(text.contains("pending_revocations"));

        let mut reopened = FileKeyStore::open(&path).unwrap();
        assert!(reopened.authenticate(&old_plaintext).is_some());
        assert!(reopened.authenticate(&new_plaintext).is_some());
        assert!(reopened.revoke_expired(159).is_empty());
        assert_eq!(reopened.revoke_expired(160), vec![old_id]);
        assert!(reopened.authenticate(&old_plaintext).is_none());
        assert!(reopened.authenticate(&new_plaintext).is_some());

        let after_reopen = FileKeyStore::open(&path).unwrap();
        assert!(after_reopen.authenticate(&old_plaintext).is_none());
        assert!(after_reopen.authenticate(&new_plaintext).is_some());

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rejects_an_unknown_store_version() {
        let path = temp_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, r#"{"version":99,"keys":[]}"#).unwrap();
        let error = FileKeyStore::open(&path).unwrap_err();
        assert!(error.to_string().contains("unsupported key store version"));

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
