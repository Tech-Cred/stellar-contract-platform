//! Persistent API-key storage.
//!
//! The in-memory [`KeyStore`] is the default for tests.
//! [`FileKeyStore`] adds durability without changing the authentication model:
//! it stores only the id, hash, role, label, and revocation state. The plaintext
//! key is returned once at creation and is never written to disk.
//!
//! The file is JSON with an explicit version. Writes go to a temporary file and
//! are renamed into place, so a crash cannot leave a half-written store.

use std::fs;
use std::path::{Path, PathBuf};

use observatory_core::{ObservatoryError, Result};
use serde::{Deserialize, Serialize};

use crate::auth::{ApiKeyRecord, ApiKeyStore, KeyStore, Principal};
use crate::rbac::Role;

/// On-disk format version.
pub const STORE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct PersistedStore {
    version: u32,
    keys: Vec<PersistedKey>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedKey {
    id: String,
    hash: String,
    role: Role,
    label: String,
    revoked: bool,
}

impl From<ApiKeyRecord> for PersistedKey {
    fn from(record: ApiKeyRecord) -> Self {
        PersistedKey {
            id: record.id,
            hash: record.hash,
            role: record.role,
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
    fn generate(&mut self, role: Role, label: &str) -> Result<(String, ApiKeyRecord)> {
        let result = self.inner.generate(role, label)?;
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
            let (plaintext, record) = store.generate(Role::Admin, "ops").unwrap();
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
            let (plaintext, record) = store.generate(Role::Developer, "ci").unwrap();
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
