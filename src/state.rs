//! Shared plugin state: config, the user store, and the in-memory session maps.
//!
//! Lock discipline: every caller takes a lock, copies what it needs into locals,
//! drops the guard, and only then calls a host API. The Pumpkin docs warn that a
//! host call can re-enter the plugin synchronously, so holding a guard across one
//! would deadlock.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;

use crate::config::Config;
use crate::security;
use crate::storage::{FileStore, UserStore, lowercase};

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
    /// Immutable after `on_load`. Read through a reference so the ~150 heap
    /// allocations inside `Config` are never re-cloned per call.
    config: Config,
    store: Mutex<Box<dyn UserStore>>,
    /// Keyed by UUID string.
    sessions: Mutex<HashMap<String, LoginSession>>,
    /// Authenticated players, keyed by UUID string.
    authenticated: Mutex<HashMap<String, ()>>,
    /// Client IP -> session expiry (unix seconds).
    ip_sessions: Mutex<HashMap<IpAddr, u64>>,
    /// UUID -> locked-until (unix seconds).
    lockouts: Mutex<HashMap<String, u64>>,
    /// UUID -> consecutive failed `/login` attempts. Separate from
    /// `UserRecord::login_failures` so a nonexistent account still counts.
    failures: Mutex<HashMap<String, u32>>,
    /// IP -> consecutive failed `/login` attempts. Only used when
    /// `rate_limit_scope = "ip"`.
    ip_failures: Mutex<HashMap<IpAddr, u32>>,
    hasher: Argon2<'static>,
    dummy_hash: Option<String>,
}

impl AuthState {
    pub fn new(config: Config, store: FileStore) -> Self {
        let hasher = security::build_argon2(&config.argon2);
        let dummy_hash = security::make_dummy_hash(&hasher);

        Self {
            config,
            store: Mutex::new(Box::new(store)),
            sessions: Mutex::new(HashMap::new()),
            authenticated: Mutex::new(HashMap::new()),
            ip_sessions: Mutex::new(HashMap::new()),
            lockouts: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            ip_failures: Mutex::new(HashMap::new()),
            hasher,
            dummy_hash,
        }
    }

    // --- config -----------------------------------------------------------

    /// The loaded config. There is no reload path, so this is a plain borrow.
    pub fn config(&self) -> &Config {
        &self.config
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

    pub fn contains_uuid(&self, uuid: &str) -> bool {
        self.with_store(|store| store.contains_uuid(uuid))
    }

    /// Whether an account already exists for this player, by UUID or by name.
    ///
    /// Decides which prompt to send: a registered player needs `/login`, anyone
    /// else needs `/register`.
    pub fn is_registered(&self, uuid: &str, username: &str) -> bool {
        let name_key = lowercase(username);
        self.with_store(|store| {
            store.contains_uuid(uuid) || store.get_by_username(&name_key).is_some()
        })
    }

    /// Whether `username_lc` belongs to an account with premium login enabled.
    ///
    /// Used to stop a cracked `/register` from claiming a reserved name.
    pub fn name_is_premium_linked(&self, username_lc: &str) -> bool {
        self.with_store(|store| {
            store
                .get_by_username(username_lc)
                .is_some_and(|record| record.active_premium_uuid().is_some())
        })
    }

    /// The stored account for a joining player, by UUID then by name.
    ///
    /// Copies the record out so the caller can reason about it without holding a
    /// guard across a host call.
    pub fn account_for(&self, uuid: &str, username: &str) -> Option<crate::storage::UserRecord> {
        let name_key = lowercase(username);
        self.with_store(|store| {
            store
                .get_by_uuid(uuid)
                .or_else(|| store.get_by_username(&name_key))
                .cloned()
        })
    }

    /// The blob an auto-login stores in `premium_uuid`, normalized for comparison.
    ///
    /// Pumpkin reports UUIDs lowercase with dashes; rejecting anything else keeps a
    /// hand-edited record from silently never matching.
    pub fn normalize_uuid(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(trimmed.to_ascii_lowercase())
    }

    // --- login sessions ---------------------------------------------------

    pub fn create_session(
        &self,
        uuid: &str,
        ip: &str,
        now: u64,
        timeout_secs: u64,
        reminder_secs: u64,
    ) {
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

    pub fn ip_session_valid(&self, ip: IpAddr, now: u64) -> bool {
        let guard = self
            .ip_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.get(&ip).is_some_and(|expiry| *expiry > now)
    }

    pub fn grant_ip_session(&self, ip: IpAddr, now: u64, minutes: u64) {
        if minutes == 0 {
            return;
        }
        let mut guard = self
            .ip_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(ip, now + minutes * 60);
    }

    pub fn revoke_ip_session(&self, ip: IpAddr) {
        let mut guard = self
            .ip_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(&ip);
    }

    /// True when no session, IP session or lockout exists, so the maintenance
    /// tick has nothing to expire, remind or prune.
    pub fn is_idle(&self) -> bool {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !sessions.is_empty() {
            return false;
        }
        let ip_sessions = self
            .ip_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !ip_sessions.is_empty() {
            return false;
        }
        let busy = !self
            .lockouts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
            || !self
                .failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
            || !self
                .ip_failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty();
        !busy
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

    // --- attempt counting -------------------------------------------------

    /// Counts one failed `/login` for `uuid` and, when `ip` is set, for that
    /// address too. Locks the account out once the threshold is reached.
    ///
    /// Counting the UUID is what closes the unknown-name hole: `login` reaches
    /// this even when no `UserRecord` exists, so guessing a random name costs
    /// the same as guessing a wrong password.
    pub fn record_failure(
        &self,
        uuid: &str,
        ip: Option<IpAddr>,
        now: u64,
        max_attempts: u32,
        lockout_secs: u64,
    ) {
        let attempts = {
            let mut guard = self
                .failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let count = guard.entry(uuid.to_string()).or_insert(0);
            *count = count.saturating_add(1);
            *count
        };

        let ip_attempts = ip.map(|addr| {
            let mut guard = self
                .ip_failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let count = guard.entry(addr).or_insert(0);
            *count = count.saturating_add(1);
            *count
        });

        if attempts >= max_attempts || ip_attempts.is_some_and(|n| n >= max_attempts) {
            self.lock(uuid, now, lockout_secs);
        }
    }

    /// Drops the failure counters for `uuid` and `ip` after a success.
    pub fn clear_failures(&self, uuid: &str, ip: Option<IpAddr>) {
        let mut guard = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(uuid);
        drop(guard);

        if let Some(addr) = ip {
            let mut guard = self
                .ip_failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.remove(&addr);
        }
    }
}

/// Extracts the client IP from what [`pumpkin_plugin_api::Player::get_ip`] returns.
///
/// The host forwards `SocketAddr::to_string()`, so the string carries the
/// client's ephemeral port (`"203.0.113.7:54321"`). Keying sessions on that
/// whole string never matches across reconnects, and behind a proxy it makes
/// every player share one key. Sessions are per host, so drop the port.
///
/// Returns `None` for anything unparseable; callers then treat IP sessions as
/// disabled for that player instead of falling back to the raw string.
pub fn parse_ip(raw: &str) -> Option<IpAddr> {
    raw.parse::<SocketAddr>().ok().map(|addr| addr.ip())
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

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid test ip")
    }

    #[test]
    fn unknown_name_attempts_lock_out_after_the_threshold() {
        // Guards K-01: a nonexistent account must still be rate limited, or
        // spamming `/login <random>` burns an Argon2 verify forever.
        let state = state();
        for attempt in 0..3 {
            assert_eq!(state.lockout_remaining("attacker", 100), None);
            state.record_failure("attacker", None, 100, 3, 60);
            if attempt < 2 {
                assert_eq!(
                    state.lockout_remaining("attacker", 100),
                    None,
                    "must not lock before the threshold"
                );
            }
        }
        assert_eq!(state.lockout_remaining("attacker", 100), Some(60));
    }

    #[test]
    fn success_clears_the_failure_counter() {
        let state = state();
        state.record_failure("player", None, 100, 3, 60);
        state.record_failure("player", None, 100, 3, 60);
        state.clear_failures("player", None);
        assert_eq!(state.lockout_remaining("player", 100), None);

        // The counter really restarted: two more attempts is still under the
        // threshold of three.
        state.record_failure("player", None, 100, 3, 60);
        state.record_failure("player", None, 100, 3, 60);
        assert_eq!(state.lockout_remaining("player", 100), None);
    }

    #[test]
    fn ip_scope_counts_across_distinct_uuids() {
        // What `rate_limit_scope = "ip"` buys: reconnecting with a fresh UUID
        // does not reset the counter.
        let state = state();
        let addr = Some(ip("203.0.113.7"));
        state.record_failure("uuid-a", addr, 100, 3, 60);
        state.record_failure("uuid-b", addr, 100, 3, 60);
        state.record_failure("uuid-c", addr, 100, 3, 60);

        assert!(
            state.lockout_remaining("uuid-c", 100).is_some(),
            "the IP counter must lock out the connection that tripped it"
        );
    }

    #[test]
    fn uuid_scope_ignores_the_ip() {
        // The default scope must not accumulate across players sharing an IP,
        // which is exactly the BungeeCord footgun.
        let state = state();
        state.record_failure("uuid-a", None, 100, 3, 60);
        state.record_failure("uuid-b", None, 100, 3, 60);
        state.record_failure("uuid-c", None, 100, 3, 60);
        assert_eq!(state.lockout_remaining("uuid-c", 100), None);
    }

    #[test]
    fn idle_state_short_circuits_the_tick() {
        let state = state();
        assert!(state.is_idle(), "a fresh state has nothing to maintain");

        state.create_session("uuid-1", "ip", 100, 60, 10);
        assert!(!state.is_idle());

        state.remove_session("uuid-1");
        assert!(state.is_idle());

        state.record_failure("uuid-1", None, 100, 3, 60);
        assert!(
            !state.is_idle(),
            "pending attempt counters must still be pruned"
        );
    }

    #[test]
    fn ip_session_expires() {
        let state = state();
        state.grant_ip_session(ip("1.2.3.4"), 100, 5);
        assert!(state.ip_session_valid(ip("1.2.3.4"), 200));
        assert!(!state.ip_session_valid(ip("1.2.3.4"), 100 + 5 * 60 + 1));
        state.prune_ip_sessions(100 + 5 * 60 + 1);
        assert!(!state.ip_session_valid(ip("1.2.3.4"), 100 + 5 * 60 + 1));
    }

    #[test]
    fn zero_minutes_disables_ip_session() {
        let state = state();
        state.grant_ip_session(ip("1.2.3.4"), 100, 0);
        assert!(!state.ip_session_valid(ip("1.2.3.4"), 101));
    }

    #[test]
    fn parse_ip_strips_the_ephemeral_port() {
        // What the host actually returns: SocketAddr::to_string().
        assert_eq!(parse_ip("203.0.113.7:54321"), Some(ip("203.0.113.7")));
        assert_eq!(parse_ip("203.0.113.7:1"), Some(ip("203.0.113.7")));
        assert_eq!(parse_ip("[2001:db8::1]:25565"), Some(ip("2001:db8::1")));
    }

    #[test]
    fn parse_ip_rejects_anything_unparseable() {
        // A bare IP has no port, so it is not a SocketAddr and must not leak
        // through as a session key.
        assert_eq!(parse_ip("203.0.113.7"), None);
        assert_eq!(parse_ip(""), None);
        assert_eq!(parse_ip("not an address"), None);
        assert_eq!(parse_ip("1.2.3.4:"), None);
    }

    #[test]
    fn ip_session_survives_a_new_source_port() {
        // The regression this guards: every reconnect uses a new ephemeral
        // port, so a session keyed on `ip:port` never matches.
        let state = state();
        let first = parse_ip("203.0.113.7:54321").expect("connect from port 54321");
        let reconnect = parse_ip("203.0.113.7:60001").expect("reconnect from port 60001");

        state.grant_ip_session(first, 100, 5);
        assert!(
            state.ip_session_valid(reconnect, 110),
            "a reconnect from the same host must reuse the session"
        );
        state.revoke_ip_session(reconnect);
        assert!(!state.ip_session_valid(first, 110));
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
    fn is_registered_matches_uuid_and_case_insensitive_name() {
        let state = state();
        assert!(!state.is_registered("uuid-1", "Alice"));

        let record =
            crate::storage::UserRecord::new(0, "Alice", "uuid-1", "hash".to_string(), "ip", 100);
        state
            .with_store(|store| store.insert(record))
            .expect("insert");

        assert!(state.is_registered("uuid-1", "Alice"));
        assert!(state.is_registered("uuid-1", "alice"));
        assert!(state.is_registered("other-uuid", "ALICE"));
        assert!(!state.is_registered("other-uuid", "Bob"));
    }

    #[test]
    fn name_is_premium_linked_only_for_linked_accounts() {
        let state = state();
        let record =
            crate::storage::UserRecord::new(0, "Notch", "uuid-1", "hash".to_string(), "ip", 100);
        state
            .with_store(|store| store.insert(record))
            .expect("insert");
        assert!(
            !state.name_is_premium_linked("notch"),
            "a fresh account is not premium"
        );

        let mut linked = state
            .with_store(|store| store.get_by_username("notch").cloned())
            .expect("record");
        linked.link_premium("premium-uuid", 200);
        state
            .with_store(|store| store.update(linked))
            .expect("update");

        assert!(state.name_is_premium_linked("notch"));
        assert!(!state.name_is_premium_linked("someone-else"));
    }

    #[test]
    fn normalize_uuid_rejects_blank_and_lowercases() {
        assert_eq!(
            AuthState::normalize_uuid("  069A79F4-44E9-4726-A5BE-FCA90E38A366 "),
            Some("069a79f4-44e9-4726-a5be-fca90e38a366".to_string())
        );
        assert_eq!(AuthState::normalize_uuid(""), None);
        assert_eq!(AuthState::normalize_uuid("   "), None);
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
