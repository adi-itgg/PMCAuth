//! JSON-backed [`UserStore`].
//!
//! The whole database is kept in memory and rewritten on change. That is fine for
//! an auth table (one row per registered player, a few KB total) and it keeps
//! every read O(1) instead of hitting the sandboxed filesystem during gameplay.
//!
//! Writes go to a temporary file and are then renamed over the real one, so a
//! crash mid-write cannot leave a truncated database behind.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{StoreError, UserRecord, UserStore};

/// Bump this and add a branch in [`FileStore::migrate`] when the layout changes.
const SCHEMA_VERSION: u32 = 1;

/// On-disk shape. Separate from [`UserRecord`] so the stored format can evolve
/// independently of the in-memory type.
#[derive(Debug, Serialize, Deserialize)]
struct Database {
    schema_version: u32,
    next_id: u64,
    users: Vec<UserRecord>,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            next_id: 1,
            users: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct FileStore {
    path: PathBuf,
    db: Database,
    by_uuid: HashMap<String, usize>,
    by_name: HashMap<String, usize>,
    dirty: bool,
}

impl FileStore {
    /// Opens the store, creating the file if it does not exist yet.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = if path.exists() {
            let raw = fs::read_to_string(path)
                .map_err(|e| StoreError::Io(format!("{}: {e}", path.display())))?;
            if raw.trim().is_empty() {
                Database::default()
            } else {
                let mut db: Database =
                    serde_json::from_str(&raw).map_err(|e| StoreError::Parse(e.to_string()))?;
                Self::migrate(&mut db)?;
                db
            }
        } else {
            let db = Database::default();
            // Persist immediately so the file exists even if nobody registers.
            Self::write_atomic(path, &db)?;
            db
        };

        let mut store = Self {
            path: path.to_path_buf(),
            db,
            by_uuid: HashMap::new(),
            by_name: HashMap::new(),
            dirty: false,
        };
        store.reindex();
        Ok(store)
    }

    /// Applies schema upgrades in place. Only version 1 exists so far.
    fn migrate(db: &mut Database) -> Result<(), StoreError> {
        match db.schema_version {
            0 => {
                // Pre-versioned file: assume the v1 layout and stamp it.
                db.schema_version = SCHEMA_VERSION;
            }
            SCHEMA_VERSION => {}
            other => {
                // Refuse to guess: silently misreading an account database is worse
                // than failing to load.
                return Err(StoreError::Parse(format!(
                    "unsupported schema_version {other} (expected {SCHEMA_VERSION})"
                )));
            }
        }

        // Repair the auto-increment counter if the file was hand-edited.
        let max_id = db.users.iter().map(|u| u.id).max().unwrap_or(0);
        if db.next_id <= max_id {
            db.next_id = max_id + 1;
        }
        Ok(())
    }

    fn reindex(&mut self) {
        self.by_uuid.clear();
        self.by_name.clear();
        for (index, user) in self.db.users.iter().enumerate() {
            self.by_uuid.insert(user.uuid.clone(), index);
            self.by_name.insert(user.username_lc.clone(), index);
        }
    }

    /// Writes to `<path>.tmp` then renames, so readers never see a partial file.
    fn write_atomic(path: &Path, db: &Database) -> Result<(), StoreError> {
        // Compact, not pretty: the file is machine-only, and this is a
        // row-per-mutation O(total records) rewrite.
        let json = serde_json::to_string(db).map_err(|e| StoreError::Parse(e.to_string()))?;
        // Append, do not replace the extension: `database_file` is configurable,
        // and `with_extension` would turn `users.db` into `users.tmp`, colliding
        // with an unrelated database in the same folder.
        let tmp = path.with_file_name({
            let mut name = path.file_name().unwrap_or_default().to_os_string();
            name.push(".tmp");
            name
        });

        fs::write(&tmp, json.as_bytes())
            .map_err(|e| StoreError::Io(format!("{}: {e}", tmp.display())))?;
        fs::rename(&tmp, path).map_err(|e| {
            // Best effort cleanup; the temp file is harmless if removal fails.
            let _ = fs::remove_file(&tmp);
            StoreError::Io(format!("{}: {e}", path.display()))
        })
    }

    fn persist(&mut self) -> Result<(), StoreError> {
        if !self.dirty {
            return Ok(());
        }
        Self::write_atomic(&self.path, &self.db)?;
        self.dirty = false;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl UserStore for FileStore {
    fn get_by_username(&self, username_lc: &str) -> Option<&UserRecord> {
        self.by_name
            .get(username_lc)
            .and_then(|index| self.db.users.get(*index))
    }

    fn get_by_uuid(&self, uuid: &str) -> Option<&UserRecord> {
        self.by_uuid
            .get(uuid)
            .and_then(|index| self.db.users.get(*index))
    }

    fn contains_uuid(&self, uuid: &str) -> bool {
        self.by_uuid.contains_key(uuid)
    }

    fn insert(&mut self, mut record: UserRecord) -> Result<(), StoreError> {
        if self.by_uuid.contains_key(&record.uuid) {
            return Err(StoreError::Duplicate(format!("uuid {}", record.uuid)));
        }
        if self.by_name.contains_key(&record.username_lc) {
            return Err(StoreError::Duplicate(format!(
                "username {}",
                record.username_lc
            )));
        }

        record.id = self.db.next_id;
        self.db.next_id += 1;

        let index = self.db.users.len();
        self.by_uuid.insert(record.uuid.clone(), index);
        self.by_name.insert(record.username_lc.clone(), index);
        self.db.users.push(record);
        self.dirty = true;
        self.persist()
    }

    fn update(&mut self, record: UserRecord) -> Result<(), StoreError> {
        let Some(&index) = self.by_uuid.get(&record.uuid) else {
            return Err(StoreError::Parse(format!("unknown uuid {}", record.uuid)));
        };

        // Usernames can change; keep the reverse index in sync.
        let old_name = self.db.users[index].username_lc.clone();
        if old_name != record.username_lc {
            if self.by_name.contains_key(&record.username_lc) {
                return Err(StoreError::Duplicate(format!(
                    "username {}",
                    record.username_lc
                )));
            }
            self.by_name.remove(&old_name);
            self.by_name.insert(record.username_lc.clone(), index);
        }

        self.db.users[index] = record;
        self.dirty = true;
        self.persist()
    }

    fn remove(&mut self, uuid: &str) -> Result<Option<UserRecord>, StoreError> {
        let Some(index) = self.by_uuid.remove(uuid) else {
            return Ok(None);
        };

        let removed = self.db.users.remove(index);
        self.by_name.remove(&removed.username_lc);
        // Removing from the middle shifts every later index; rebuild instead of
        // hand-patching, the table is small.
        self.reindex();
        self.dirty = true;
        self.persist()?;
        Ok(Some(removed))
    }

    fn len(&self) -> usize {
        self.db.users.len()
    }

    fn flush(&self) -> Result<(), StoreError> {
        // Every mutation already persists, so this only has to handle the case
        // where an earlier write failed and left the flag set.
        if self.dirty {
            Self::write_atomic(&self.path, &self.db)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "pmcauth-test-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample(name: &str, uuid: &str) -> UserRecord {
        UserRecord::new(0, name, uuid, "hash".into(), "127.0.0.1", 42)
    }

    #[test]
    fn creates_file_on_open() {
        let dir = TempDir::new("create");
        let path = dir.path().join("users.json");
        let store = FileStore::open(&path).expect("open");
        assert!(path.exists());
        assert!(store.is_empty());
    }

    #[test]
    fn insert_lookup_and_persist_across_reopen() {
        let dir = TempDir::new("persist");
        let path = dir.path().join("users.json");

        {
            let mut store = FileStore::open(&path).expect("open");
            store.insert(sample("Notch", "uuid-1")).expect("insert");
            assert_eq!(store.len(), 1);
            assert_eq!(store.get_by_username("notch").map(|u| u.id), Some(1));
            assert_eq!(
                store.get_by_uuid("uuid-1").map(|u| u.username.as_str()),
                Some("Notch")
            );
        }

        let reopened = FileStore::open(&path).expect("reopen");
        assert_eq!(reopened.len(), 1);
        assert!(reopened.get_by_username("notch").is_some());
    }

    #[test]
    fn rejects_duplicate_username_case_insensitively() {
        let dir = TempDir::new("dupe");
        let mut store = FileStore::open(&dir.path().join("users.json")).expect("open");
        store.insert(sample("Notch", "uuid-1")).expect("first");
        let err = store
            .insert(sample("NOTCH", "uuid-2"))
            .expect_err("must reject");
        assert!(matches!(err, StoreError::Duplicate(_)));
    }

    #[test]
    fn rejects_duplicate_uuid() {
        let dir = TempDir::new("dupe-uuid");
        let mut store = FileStore::open(&dir.path().join("users.json")).expect("open");
        store.insert(sample("Alice", "uuid-1")).expect("first");
        let err = store
            .insert(sample("Bob", "uuid-1"))
            .expect_err("must reject");
        assert!(matches!(err, StoreError::Duplicate(_)));
    }

    #[test]
    fn update_and_remove_keep_indexes_consistent() {
        let dir = TempDir::new("update");
        let mut store = FileStore::open(&dir.path().join("users.json")).expect("open");
        store.insert(sample("Alice", "uuid-1")).expect("a");
        store.insert(sample("Bob", "uuid-2")).expect("b");

        let mut alice = store.get_by_uuid("uuid-1").expect("alice").clone();
        alice.password_hash = "new-hash".into();
        store.update(alice).expect("update");

        let removed = store.remove("uuid-1").expect("remove").expect("existed");
        assert_eq!(removed.username, "Alice");
        assert!(store.get_by_uuid("uuid-1").is_none());
        assert!(store.get_by_username("alice").is_none());
        // Bob must still resolve after the reindex.
        assert_eq!(
            store.get_by_username("bob").map(|u| u.uuid.as_str()),
            Some("uuid-2")
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let dir = TempDir::new("schema");
        let path = dir.path().join("users.json");
        fs::write(&path, r#"{"schema_version":99,"next_id":1,"users":[]}"#).expect("write");
        let err = FileStore::open(&path).expect_err("must refuse to load an unknown schema");
        assert!(matches!(err, StoreError::Parse(_)));
    }

    #[test]
    fn repairs_stale_next_id() {
        let dir = TempDir::new("nextid");
        let path = dir.path().join("users.json");
        fs::write(
            &path,
            r#"{"schema_version":1,"next_id":1,"users":[{"id":7,"username":"A","username_lc":"a","uuid":"u","password_hash":"h","registered_ip":"i","last_ip":"i","registered_at":1,"last_login":1,"login_failures":0}]}"#,
        )
        .expect("write");

        let mut store = FileStore::open(&path).expect("open");
        store.insert(sample("B", "uuid-b")).expect("insert");
        assert_eq!(store.get_by_username("b").map(|u| u.id), Some(8));
    }
}
