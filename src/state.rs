//! Shared plugin state: config, the user store, and the in-memory session maps.
//!
//! Lock discipline: every caller takes a lock, copies what it needs into locals,
//! drops the guard, and only then calls a host API. The Pumpkin docs warn that a
//! host call can re-enter the plugin synchronously, so holding a guard across one
//! would deadlock.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;

use crate::config::Config;
use crate::security;
use crate::storage::{FileStore, UserStore};

/// A player who is currently connected but has not authenticated yet.
#[derive(Debug, Clone)]
pub struct LoginSession {
    /// Unix timestamp at which the login timeout fires.
    pub deadline: u64,
    /// Unix timestamp of the next reminder message.
    pub next_reminder: u64,
    /// Cached IP so leave-handling does not need a player handle.
    pub ip: String,
}

/// Everything the plugin needs at runtime. Built once in `on_load`, shared via `Arc`.
pub struct AuthState {
    config: RwLock<Config>,
    store: Mutex<Box<dyn UserStore>>,
    /// Keyed by UUID string.
    sessions: Mutex<HashMap<String, LoginSession>>,
    /// Authenticated players, keyed by UUID string.
    authenticated: Mutex<HashMap<String, ()>>,
    /// IP -> session expiry (unix seconds).
    ip_sessions: Mutex<HashMap<String, u64>>,
    /// UUID -> locked-until (unix seconds).
    lockouts: Mutex<HashMap<String, u64>>,
    hasher: Argon2<'static>,
    dummy_hash: Option<String>,
}

impl AuthState {
    pub fn new(config: Config, store: FileStore) -> Self {
        let hasher = security::build_argon2(&config.argon2);
        let dummy_hash = security::make_dummy_hash(&hasher);

        Self {
            config: RwLock::new(config),
            store: Mutex::new(Box::new(store)),
            sessions: Mutex::new(HashMap::new()),
            authenticated: Mutex::new(HashMap::new()),
            ip_sessions: Mutex::new(HashMap::new()),
            lockouts: Mutex::new(HashMap::new()),
            hasher,
            dummy_hash,
        }
    }

    // --- config -----------------------------------------------------------

    /// Copies the config out. Never hold the returned clone's lock.
    pub fn config(&self) -> Config {
        self.config
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    pub fn set_config(&self, config: Config) {
        if let Ok(mut guard) = self.config.write() {
            *guard = config;
        }
    }

    // --- hashing ----------------------------------------------------------

    pub fn hasher(&self) -> &Argon2<'static> {
        &self.hasher
    }

    pub fn dummy_hash(&self) -> Option<&str> {
        self.dummy_hash.as_deref()
    }

    // --- store ------------------------------------------------------------

    /// Runs `f` with the store locked. Keep `f` short and never call a host API
    /// inside it.
    pub fn with_store<R>(&self, f: impl FnOnce(&mut dyn UserStore) -> R) -> R {
        let mut guard = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(guard.as_mut())
    }

    pub fn flush_store(&self) -> Result<(), crate::storage::StoreError> {
        self.with_store(|store| store.flush())
    }

    // --- login sessions ---------------------------------------------------

    pub fn create_session(&self, uuid: &str, ip: &str, now: u64, timeout_secs: u64, reminder_secs: u64) {
        let session = LoginSession {
            deadline: now + timeout_secs,
            next_reminder: now + reminder_secs.max(1),
            ip: ip.to_string(),
        };
        let mut guard = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(uuid.to_string(), session);
    }

    pub fn session(&self, uuid: &str) -> Option<LoginSession> {
        let guard = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.get(uuid).cloned()
    }

    /// Schedules the next reminder and returns the updated session.
    pub fn bump_reminder(&self, uuid: &str, interval_secs: u64) -> Option<LoginSession> {
        let mut guard = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let session = guard.get_mut(uuid)?;
        session.next_reminder = now_unix() + interval_secs.max(1);
        Some(session.clone())
    }

    pub fn remove_session(&self, uuid: &str) -> Option<LoginSession> {
        let mut guard = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(uuid)
    }

    /// UUIDs of players whose login deadline has passed.
    pub fn expired_sessions(&self, now: u64) -> Vec<String> {
        let guard = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .iter()
            .filter(|(_, session)| session.deadline <= now)
            .map(|(uuid, _)| uuid.clone())
            .collect()
    }

    /// UUIDs whose reminder is due.
    pub fn due_reminders(&self, now: u64) -> Vec<(String, LoginSession)> {
        let guard = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .iter()
            .filter(|(_, session)| session.next_reminder <= now)
            .map(|(uuid, session)| (uuid.clone(), session.clone()))
            .collect()
    }

    // --- authenticated ----------------------------------------------------

    pub fn is_authenticated(&self, uuid: &str) -> bool {
        let guard = self
            .authenticated
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.contains_key(uuid)
    }

    pub fn set_authenticated(&self, uuid: &str) {
        let mut guard = self
            .authenticated
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(uuid.to_string(), ());
    }

    pub fn clear_authenticated(&self, uuid: &str) -> bool {
        let mut guard = self
            .authenticated
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(uuid).is_some()
    }

    // --- IP sessions ------------------------------------------------------

    pub fn ip_session_valid(&self, ip: &str, now: u64) -> bool {
        let guard = self
            .ip_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.get(ip).is_some_and(|expiry| *expiry > now)
    }

    pub fn grant_ip_session(&self, ip: &str, now: u64, minutes: u64) {
        if minutes == 0 {
            return;
        }
        let mut guard = self
            .ip_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(ip.to_string(), now + minutes * 60);
    }

    pub fn revoke_ip_session(&self, ip: &str) {
        let mut guard = self
            .ip_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(ip);
    }

    /// Drops expired IP sessions so the map cannot grow without bound.
    pub fn prune_ip_sessions(&self, now: u64) {
        let mut guard = self
            .ip_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.retain(|_, expiry| *expiry > now);
    }

    // --- lockouts ---------------------------------------------------------

    pub fn lockout_remaining(&self, uuid: &str, now: u64) -> Option<u64> {
        let guard = self
            .lockouts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .get(uuid)
            .filter(|until| **until > now)
            .map(|until| until - now)
    }

    pub fn lock(&self, uuid: &str, now: u64, seconds: u64) {
        let mut guard = self
            .lockouts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(uuid.to_string(), now + seconds);
    }

    pub fn clear_lockout(&self, uuid: &str) {
        let mut guard = self
            .lockouts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(uuid);
    }

    pub fn prune_lockouts(&self, now: u64) {
        let mut guard = self
            .lockouts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.retain(|_, until| *until > now);
    }
}

/// Current unix time in seconds. `SystemTime` maps to `wasi:clocks/wall-clock`
/// on `wasm32-wasip2`; the fallback keeps the plugin alive if the clock is
/// unavailable rather than panicking.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique per call: tests run in parallel and must not share a directory.
    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn state() -> AuthState {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "pmcauth-state-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        let store = FileStore::open(&path.join("users.json")).expect("store");
        AuthState::new(Config::default(), store)
    }

    #[test]
    fn session_lifecycle() {
        let state = state();
        state.create_session("uuid-1", "1.2.3.4", 100, 60, 10);
        let session = state.session("uuid-1").expect("session");
        assert_eq!(session.deadline, 160);
        assert_eq!(session.next_reminder, 110);
        assert!(state.remove_session("uuid-1").is_some());
        assert!(state.session("uuid-1").is_none());
    }

    #[test]
    fn expired_sessions_are_reported() {
        let state = state();
        state.create_session("a", "ip", 100, 10, 5);
        state.create_session("b", "ip", 100, 100, 5);
        let expired = state.expired_sessions(150);
        assert_eq!(expired, vec!["a".to_string()]);
    }

    #[test]
    fn ip_session_expires() {
        let state = state();
        state.grant_ip_session("1.2.3.4", 100, 5);
        assert!(state.ip_session_valid("1.2.3.4", 200));
        assert!(!state.ip_session_valid("1.2.3.4", 100 + 5 * 60 + 1));
        state.prune_ip_sessions(100 + 5 * 60 + 1);
        assert!(!state.ip_session_valid("1.2.3.4", 100 + 5 * 60 + 1));
    }

    #[test]
    fn zero_minutes_disables_ip_session() {
        let state = state();
        state.grant_ip_session("1.2.3.4", 100, 0);
        assert!(!state.ip_session_valid("1.2.3.4", 101));
    }

    #[test]
    fn lockout_expires() {
        let state = state();
        state.lock("uuid-1", 100, 60);
        assert_eq!(state.lockout_remaining("uuid-1", 120), Some(40));
        assert_eq!(state.lockout_remaining("uuid-1", 161), None);
        state.prune_lockouts(161);
        assert_eq!(state.lockout_remaining("uuid-1", 161), None);
    }

    #[test]
    fn auth_flag_toggles() {
        let state = state();
        assert!(!state.is_authenticated("uuid-1"));
        state.set_authenticated("uuid-1");
        assert!(state.is_authenticated("uuid-1"));
        assert!(state.clear_authenticated("uuid-1"));
        assert!(!state.is_authenticated("uuid-1"));
    }

    #[test]
    fn auth_state_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuthState>();
    }

}
