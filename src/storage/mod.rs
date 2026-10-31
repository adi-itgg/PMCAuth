//! Storage layer.
//!
//! Auth logic talks to [`UserStore`] only, so the JSON backend can be swapped for
//! something else (SQLite, a remote service) without touching `auth.rs`.

pub mod file_store;

use serde::{Deserialize, Serialize};

pub use file_store::FileStore;

/// One registered account.
///
/// `username` keeps the casing the player joined with (for display); `username_lc`
/// is the lookup key and is always lowercase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: u64,
    pub username: String,
    pub username_lc: String,
    pub uuid: String,
    /// PHC string including algorithm, params, salt and hash.
    pub password_hash: String,
    pub registered_ip: String,
    pub last_ip: String,
    pub registered_at: u64,
    pub last_login: u64,
    pub login_failures: u32,
}

impl UserRecord {
    pub fn new(
        id: u64,
        username: &str,
        uuid: &str,
        password_hash: String,
        ip: &str,
        now: u64,
    ) -> Self {
        Self {
            id,
            username: username.to_string(),
            username_lc: lowercase(username),
            uuid: uuid.to_string(),
            password_hash,
            registered_ip: ip.to_string(),
            last_ip: ip.to_string(),
            registered_at: now,
            last_login: now,
            login_failures: 0,
        }
    }
}

/// Case-insensitive username key. Player names are ASCII-only in Minecraft, so a
/// simple lowercase is enough and avoids a Unicode case-folding dependency.
pub fn lowercase(username: &str) -> String {
    username.to_ascii_lowercase()
}

#[derive(Debug)]
pub enum StoreError {
    Io(String),
    Parse(String),
    Duplicate(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "store io error: {e}"),
            Self::Parse(e) => write!(f, "store parse error: {e}"),
            Self::Duplicate(what) => write!(f, "duplicate entry: {what}"),
        }
    }
}

/// Backend-agnostic account storage.
///
/// Reads are by reference to keep the hot path allocation-free; callers copy out
/// whatever they need before touching a host API.
pub trait UserStore: Send + Sync {
    fn get_by_username(&self, username_lc: &str) -> Option<&UserRecord>;
    fn get_by_uuid(&self, uuid: &str) -> Option<&UserRecord>;
    fn insert(&mut self, record: UserRecord) -> Result<(), StoreError>;
    fn update(&mut self, record: UserRecord) -> Result<(), StoreError>;
    /// Removes the account for `uuid`, returning it if it existed.
    fn remove(&mut self, uuid: &str) -> Result<Option<UserRecord>, StoreError>;
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Persists pending changes. A no-op for backends that write through.
    fn flush(&self) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_is_ascii_insensitive() {
        assert_eq!(lowercase("Notch"), "notch");
        assert_eq!(lowercase("NOTCH"), "notch");
        assert_eq!(lowercase("notch"), "notch");
    }

    #[test]
    fn new_record_sets_lookup_key_and_timestamps() {
        let record = UserRecord::new(1, "Notch", "uuid-1", "hash".into(), "1.2.3.4", 1000);
        assert_eq!(record.username, "Notch");
        assert_eq!(record.username_lc, "notch");
        assert_eq!(record.registered_at, 1000);
        assert_eq!(record.last_login, 1000);
        assert_eq!(record.registered_ip, "1.2.3.4");
        assert_eq!(record.login_failures, 0);
    }
}
