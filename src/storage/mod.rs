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
    /// Whether this account opted into premium login.
    ///
    /// Defaulted so a schema-1 database loads every existing account as cracked.
    #[serde(default)]
    pub premium_linked: bool,
    /// The Mojang-issued UUID the account is bound to.
    ///
    /// Deliberately not the same field as [`Self::uuid`]: in offline mode the
    /// connection UUID is derived from the name, so the two only agree when the
    /// connection really was authenticated.
    #[serde(default)]
    pub premium_uuid: Option<String>,
    /// Unix timestamp of when the premium link was created.
    #[serde(default)]
    pub premium_linked_at: Option<u64>,
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
            premium_linked: false,
            premium_uuid: None,
            premium_linked_at: None,
        }
    }

    /// Binds the account to a Mojang UUID and turns premium login on.
    pub fn link_premium(&mut self, premium_uuid: &str, now: u64) {
        self.premium_linked = true;
        self.premium_uuid = Some(premium_uuid.to_string());
        self.premium_linked_at = Some(now);
    }

    /// Drops the premium link, returning the account to the password flow.
    pub fn unlink_premium(&mut self) {
        self.premium_linked = false;
        self.premium_uuid = None;
        self.premium_linked_at = None;
    }

    /// The bound UUID, but only while the link is actually active.
    ///
    /// Both fields are checked so a half-written record (hand-edited file, or a
    /// future schema) can never authorise an auto-login.
    pub fn active_premium_uuid(&self) -> Option<&str> {
        if !self.premium_linked {
            return None;
        }
        self.premium_uuid.as_deref().filter(|uuid| !uuid.is_empty())
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
    /// Existence check by UUID, without materialising a record. Defaults to
    /// `get_by_uuid(..).is_some()` so implementors only override it if the
    /// lookup alone is cheaper than the record.
    fn contains_uuid(&self, uuid: &str) -> bool {
        self.get_by_uuid(uuid).is_some()
    }
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

    #[test]
    fn new_record_starts_cracked() {
        let record = UserRecord::new(1, "Notch", "uuid-1", "hash".into(), "1.2.3.4", 1000);
        assert!(!record.premium_linked);
        assert_eq!(record.premium_uuid, None);
        assert_eq!(record.premium_linked_at, None);
        assert_eq!(record.active_premium_uuid(), None);
    }

    #[test]
    fn link_and_unlink_premium_round_trip() {
        let mut record =
            UserRecord::new(1, "Notch", "offline-uuid", "hash".into(), "1.2.3.4", 1000);
        record.link_premium("premium-uuid", 2000);

        assert!(record.premium_linked);
        assert_eq!(record.premium_uuid.as_deref(), Some("premium-uuid"));
        assert_eq!(record.premium_linked_at, Some(2000));
        assert_eq!(record.active_premium_uuid(), Some("premium-uuid"));
        // The connection UUID is untouched: it is a different field on purpose.
        assert_eq!(record.uuid, "offline-uuid");

        record.unlink_premium();
        assert!(!record.premium_linked);
        assert_eq!(record.premium_uuid, None);
        assert_eq!(record.active_premium_uuid(), None);
    }

    #[test]
    fn half_written_premium_link_is_not_active() {
        // Guards against a hand-edited file: `premium_uuid` without the flag, or
        // the flag with an empty UUID, must never authorise an auto-login.
        let mut record = UserRecord::new(1, "Notch", "uuid-1", "hash".into(), "1.2.3.4", 1000);
        record.premium_uuid = Some("premium-uuid".into());
        assert_eq!(record.active_premium_uuid(), None);

        record.premium_linked = true;
        record.premium_uuid = Some(String::new());
        assert_eq!(record.active_premium_uuid(), None);
    }

    #[test]
    fn record_without_premium_fields_deserializes_as_cracked() {
        // Exactly the shape a schema-1 users.json has.
        let json = r#"{
            "id": 1, "username": "Notch", "username_lc": "notch", "uuid": "uuid-1",
            "password_hash": "h", "registered_ip": "i", "last_ip": "i",
            "registered_at": 1, "last_login": 1, "login_failures": 0
        }"#;

        let record: UserRecord = serde_json::from_str(json).expect("schema-1 record must load");
        assert!(!record.premium_linked);
        assert_eq!(record.premium_uuid, None);
        assert_eq!(record.active_premium_uuid(), None);
    }
}
