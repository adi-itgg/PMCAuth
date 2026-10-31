//! Authentication logic.
//!
//! Deliberately free of Pumpkin API calls: everything here takes plain data and
//! returns an [`AuthReply`]. That keeps the rules testable on the host and makes
//! the command layer a thin translation shell.

use std::net::IpAddr;

use crate::config::{Config, Premium, RateLimitScope};
use crate::security::{self, PasswordError};
use crate::state::{AuthState, now_unix, parse_ip};
use crate::storage::{UserRecord, lowercase};

/// A rendered-later message: a config key plus placeholder values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthReply {
    pub key: &'static str,
    pub vars: Vec<(&'static str, String)>,
}

impl AuthReply {
    pub fn ok(key: &'static str) -> Self {
        Self {
            key,
            vars: Vec::new(),
        }
    }

    pub fn fail(key: &'static str) -> Self {
        Self {
            key,
            vars: Vec::new(),
        }
    }

    pub fn with(key: &'static str, vars: Vec<(&'static str, String)>) -> Self {
        Self { key, vars }
    }

    /// Substitutes `{name}` placeholders in the configured message, in `locale`.
    pub fn render(&self, config: &Config, locale: &str) -> String {
        let mut text = config.message(self.key, locale).to_string();
        for (name, value) in &self.vars {
            text = text.replace(&format!("{{{name}}}"), value);
        }
        text
    }
}

impl From<PasswordError> for AuthReply {
    fn from(error: PasswordError) -> Self {
        match error {
            PasswordError::TooShort { min } => {
                AuthReply::with("password_too_short", vec![("min", min.to_string())])
            }
            PasswordError::TooLong { max } => {
                AuthReply::with("password_too_long", vec![("max", max.to_string())])
            }
            PasswordError::SameAsUsername => AuthReply::fail("password_is_username"),
            // Never surface hashing internals to the player.
            PasswordError::Hash(_) => AuthReply::fail("internal_error"),
        }
    }
}

/// Where the proof that a connection really is Mojang-authenticated comes from.
///
/// The login events carry no "authenticated" flag, so this is reconstructed from
/// what the host already did for us. See `plans/premium-login-plan.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PremiumAnchor {
    /// Nothing proves the connection was authenticated. Auto-login is impossible.
    None,
    /// The server itself is in online mode, so it ran the Mojang handshake for
    /// this connection and the UUID is Mojang-issued.
    OnlineMode,
    /// The profile arrived with a `textures` property, which only an
    /// authenticating proxy or online mode produces.
    ForwardedProfile,
}

impl PremiumAnchor {
    pub const fn is_some(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// The outcome of the premium check for one join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PremiumDecision {
    /// Auto-login. Every condition held.
    AutoLogin { anchor: PremiumAnchor },
    /// Fall through to the existing password flow. Never an error path that logs in.
    PasswordFlow(PasswordFlowReason),
}

/// Why the premium path declined, for the decision log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordFlowReason {
    Disabled,
    NotRegistered,
    NotLinked,
    UuidMismatch,
    NoAnchor,
}

/// Decides whether a joining player may skip the password.
///
/// Deliberately takes plain data instead of a `Player` so the rule table is
/// testable on the host and cannot accidentally be reordered around host calls.
///
/// Every failure returns [`PremiumDecision::PasswordFlow`]; there is no input that
/// turns an error into authentication.
pub fn autologin_decision(
    premium: &Premium,
    anchor: PremiumAnchor,
    connection_uuid: &str,
    record: Option<&UserRecord>,
) -> PremiumDecision {
    use PasswordFlowReason as Reason;

    if !premium.enabled {
        return PremiumDecision::PasswordFlow(Reason::Disabled);
    }

    let Some(record) = record else {
        return PremiumDecision::PasswordFlow(Reason::NotRegistered);
    };

    let Some(premium_uuid) = record.active_premium_uuid() else {
        return PremiumDecision::PasswordFlow(Reason::NotLinked);
    };

    // The UUID is the whole point: names change hands, UUIDs do not.
    if !premium_uuid.eq_ignore_ascii_case(connection_uuid) {
        return PremiumDecision::PasswordFlow(Reason::UuidMismatch);
    }

    if !anchor.is_some() {
        return PremiumDecision::PasswordFlow(Reason::NoAnchor);
    }

    PremiumDecision::AutoLogin { anchor }
}

/// Whether a link may be created right now.
///
/// Stricter than [`autologin_decision`]: a link is a lasting grant, so it needs an
/// anchor *and* the evidence that the current profile came from that anchor. On a
/// direct offline server with `trust_forwarded_profile = true` there is no
/// textures property, so this refuses instead of binding a name anyone could take.
pub fn can_link(premium: &Premium, anchor: PremiumAnchor, has_textures: bool) -> bool {
    if !premium.enabled {
        return false;
    }
    match anchor {
        PremiumAnchor::None => false,
        // Online mode already proves ownership; the profile may still lack skins.
        PremiumAnchor::OnlineMode => true,
        PremiumAnchor::ForwardedProfile => !premium.link_requires_textures || has_textures,
    }
}

/// Registers a new account. The player ends up authenticated on success.
pub fn register(
    state: &AuthState,
    uuid: &str,
    username: &str,
    ip: &str,
    password: &str,
    confirm: &str,
) -> AuthReply {
    let config = state.config();

    if state.is_authenticated(uuid) {
        return AuthReply::fail("already_logged_in");
    }
    if password != confirm {
        return AuthReply::fail("password_mismatch");
    }

    let name_key = lowercase(username);

    let taken = state.with_store(|store| {
        store.get_by_uuid(uuid).is_some() || store.get_by_username(&name_key).is_some()
    });
    if taken {
        return AuthReply::fail("already_registered");
    }

    // A name bound to a premium account must not be re-registered as a cracked
    // account, which would hand it to whoever connects with that name first.
    // This is a local check only: the plugin never asks Mojang whether a name
    // exists there.
    if config.premium.enabled
        && config.premium.block_linked_names
        && state.name_is_premium_linked(&name_key)
    {
        return AuthReply::fail("premium_name_blocked");
    }

    if let Err(error) = security::validate_password(
        password,
        username,
        config.general.min_password_length,
        config.general.max_password_length,
    ) {
        return error.into();
    }

    let hash = match security::hash_password(state.hasher(), password) {
        Ok(hash) => hash,
        Err(error) => return error.into(),
    };

    let now = now_unix();
    let record = UserRecord::new(0, username, uuid, hash, ip, now);

    if state.with_store(|store| store.insert(record)).is_err() {
        return AuthReply::fail("internal_error");
    }

    // Registration counts as authentication.
    state.remove_session(uuid);
    state.set_authenticated(uuid);
    if let Some(ip) = parse_ip(ip) {
        state.grant_ip_session(ip, now, config.general.session_minutes);
    }

    AuthReply::ok("register_success")
}

/// Verifies a password and, on success, marks the player authenticated.
pub fn login(state: &AuthState, uuid: &str, username: &str, ip: &str, password: &str) -> AuthReply {
    let config = state.config();
    let now = now_unix();

    if state.is_authenticated(uuid) {
        return AuthReply::fail("already_logged_in");
    }

    if let Some(remaining) = state.lockout_remaining(uuid, now) {
        return AuthReply::with(
            "kicked_bruteforce",
            vec![("seconds", remaining.to_string())],
        );
    }

    let name_key = lowercase(username);
    let record = state.with_store(|store| {
        store
            .get_by_uuid(uuid)
            .or_else(|| store.get_by_username(&name_key))
            .cloned()
    });

    let addr = match config.general.rate_limit_scope {
        RateLimitScope::Ip => parse_ip(ip),
        RateLimitScope::Uuid => None,
    };

    let Some(record) = record else {
        // Burn the same Argon2 work as a real check so response time does not
        // reveal whether the account exists.
        if let Some(dummy) = state.dummy_hash() {
            security::verify_dummy(state.hasher(), password, dummy);
        }
        // Count it, or guessing random names forever is free: `record_failure`
        // below is unreachable when no record exists.
        state.record_failure(
            uuid,
            addr,
            now,
            config.general.max_login_attempts,
            config.general.lockout_seconds,
        );
        return AuthReply::fail("not_registered");
    };

    if !security::verify_password(state.hasher(), password, &record.password_hash) {
        return record_failure(state, config, uuid, record, addr);
    }

    let mut record = record;
    record.last_ip = ip.to_string();
    record.last_login = now;
    record.login_failures = 0;
    let _ = state.with_store(|store| store.update(record));

    state.clear_lockout(uuid);
    state.clear_failures(uuid, addr);
    state.remove_session(uuid);
    state.set_authenticated(uuid);
    if let Some(addr) = parse_ip(ip) {
        state.grant_ip_session(addr, now, config.general.session_minutes);
    }

    AuthReply::ok("login_success")
}

/// Counts a failed attempt and locks the account out when the limit is reached.
fn record_failure(
    state: &AuthState,
    config: &Config,
    uuid: &str,
    mut record: UserRecord,
    addr: Option<IpAddr>,
) -> AuthReply {
    record.login_failures = record.login_failures.saturating_add(1);
    let _ = state.with_store(|store| store.update(record));

    state.record_failure(
        uuid,
        addr,
        now_unix(),
        config.general.max_login_attempts,
        config.general.lockout_seconds,
    );

    AuthReply::fail("login_failed")
}

// --- premium login --------------------------------------------------------

/// Enables premium login for an authenticated account.
///
/// `anchor` and `has_textures` come from the live connection, so this refuses
/// whenever the current session cannot prove it is Mojang-authenticated.
pub fn premium_link(
    state: &AuthState,
    uuid: &str,
    username: &str,
    anchor: PremiumAnchor,
    has_textures: bool,
) -> AuthReply {
    let config = state.config();

    if !config.premium.enabled {
        return AuthReply::fail("premium_unavailable");
    }
    if !state.is_authenticated(uuid) {
        return AuthReply::fail("not_logged_in");
    }
    if !can_link(&config.premium, anchor, has_textures) {
        // Either no anchor at all (feature misconfigured) or a forwarded claim
        // with no profile behind it.
        return match anchor {
            PremiumAnchor::None => AuthReply::fail("premium_unavailable"),
            _ => AuthReply::fail("premium_needs_profile"),
        };
    }

    // Same lookup as `/login`: by UUID, then by name. The fallback is what lets an
    // account created in offline mode link after a proxy is installed, because the
    // connection UUID changes but the account row is still keyed by the old one.
    let Some(mut record) = state.account_for(uuid, username) else {
        return AuthReply::fail("not_registered");
    };

    if record.active_premium_uuid() == Some(uuid) {
        return AuthReply::fail("premium_link_already");
    }

    // Binds the UUID the connection actually has, which is the value auto-login
    // will compare against on the next join.
    record.link_premium(uuid, now_unix());
    if state.with_store(|store| store.update(record)).is_err() {
        return AuthReply::fail("internal_error");
    }

    AuthReply::ok("premium_link_success")
}

/// Disables premium login for the calling account, restoring the password flow.
pub fn premium_unlink(state: &AuthState, uuid: &str) -> AuthReply {
    if !state.config().premium.enabled {
        return AuthReply::fail("premium_unavailable");
    }

    let Some(mut record) = state.with_store(|store| store.get_by_uuid(uuid).cloned()) else {
        return AuthReply::fail("not_registered");
    };

    if record.active_premium_uuid().is_none() {
        return AuthReply::fail("premium_unlink_not_linked");
    }

    record.unlink_premium();
    if state.with_store(|store| store.update(record)).is_err() {
        return AuthReply::fail("internal_error");
    }

    AuthReply::ok("premium_unlink_success")
}

/// Reports whether the calling account has premium login enabled.
pub fn premium_status(state: &AuthState, uuid: &str, username: &str) -> AuthReply {
    let record = state.account_for(uuid, username);

    match record.as_ref().and_then(UserRecord::active_premium_uuid) {
        Some(premium_uuid) => AuthReply::with(
            "premium_status_linked",
            vec![("uuid", premium_uuid.to_string())],
        ),
        None => AuthReply::fail("premium_status_not_linked"),
    }
}

/// Operator action: bind an account to the UUID of its current session.
pub fn admin_premium_set(
    state: &AuthState,
    target_lc: &str,
    anchor: PremiumAnchor,
    has_textures: bool,
) -> AuthReply {
    let config = state.config();

    if !config.premium.enabled {
        return AuthReply::fail("premium_unavailable");
    }

    let Some(mut record) = state.with_store(|store| store.get_by_username(target_lc).cloned())
    else {
        return AuthReply::fail("admin_unknown_account");
    };

    let target_uuid = record.uuid.clone();

    if !can_link(&config.premium, anchor, has_textures) {
        return match anchor {
            PremiumAnchor::None => AuthReply::fail("premium_unavailable"),
            _ => AuthReply::fail("premium_needs_profile"),
        };
    }
    if record.active_premium_uuid() == Some(target_uuid.as_str()) {
        return AuthReply::fail("premium_link_already");
    }

    record.link_premium(&target_uuid, now_unix());
    if state.with_store(|store| store.update(record)).is_err() {
        return AuthReply::fail("internal_error");
    }

    AuthReply::ok("admin_done")
}

/// Operator action: drop an account's premium link. Works offline.
pub fn admin_premium_unset(state: &AuthState, target_lc: &str) -> AuthReply {
    let Some(mut record) = state.with_store(|store| store.get_by_username(target_lc).cloned())
    else {
        return AuthReply::fail("admin_unknown_account");
    };

    if record.active_premium_uuid().is_none() {
        return AuthReply::fail("premium_unlink_not_linked");
    }

    record.unlink_premium();
    if state.with_store(|store| store.update(record)).is_err() {
        return AuthReply::fail("internal_error");
    }

    AuthReply::ok("admin_done")
}

/// Logs an authenticated player out and forgets their IP session.
pub fn logout(state: &AuthState, uuid: &str, ip: &str) -> AuthReply {
    if !state.clear_authenticated(uuid) {
        return AuthReply::fail("not_logged_in");
    }
    if let Some(ip) = parse_ip(ip) {
        state.revoke_ip_session(ip);
    }
    AuthReply::ok("logout_success")
}

/// Changes the password of an authenticated player.
pub fn change_password(
    state: &AuthState,
    uuid: &str,
    username: &str,
    old_password: &str,
    new_password: &str,
) -> AuthReply {
    let config = state.config();

    if !state.is_authenticated(uuid) {
        return AuthReply::fail("not_logged_in");
    }

    let Some(mut record) = state.with_store(|store| store.get_by_uuid(uuid).cloned()) else {
        return AuthReply::fail("not_registered");
    };

    if !security::verify_password(state.hasher(), old_password, &record.password_hash) {
        return AuthReply::fail("login_failed");
    }

    if let Err(error) = security::validate_password(
        new_password,
        username,
        config.general.min_password_length,
        config.general.max_password_length,
    ) {
        return error.into();
    }

    match security::hash_password(state.hasher(), new_password) {
        Ok(hash) => record.password_hash = hash,
        Err(error) => return error.into(),
    }

    if state.with_store(|store| store.update(record)).is_err() {
        return AuthReply::fail("internal_error");
    }

    AuthReply::ok("change_success")
}

/// Removes an account by lowercase name.
pub fn admin_unregister(state: &AuthState, target_lc: &str) -> AuthReply {
    let uuid = state.with_store(|store| store.get_by_username(target_lc).map(|r| r.uuid.clone()));

    let Some(uuid) = uuid else {
        return AuthReply::fail("admin_unknown_account");
    };

    match state.with_store(|store| store.remove(&uuid)) {
        Ok(Some(_)) => {
            state.clear_authenticated(&uuid);
            state.remove_session(&uuid);
            state.clear_lockout(&uuid);
            AuthReply::ok("admin_done")
        }
        Ok(None) => AuthReply::fail("admin_unknown_account"),
        Err(_) => AuthReply::fail("internal_error"),
    }
}

/// Marks an existing account as authenticated without a password.
pub fn admin_force_login(state: &AuthState, uuid: &str, ip: &str) -> AuthReply {
    let exists = state.with_store(|store| store.contains_uuid(uuid));
    if !exists {
        return AuthReply::fail("admin_unknown_account");
    }

    state.remove_session(uuid);
    state.clear_lockout(uuid);
    state.set_authenticated(uuid);
    if let Some(ip) = parse_ip(ip) {
        state.grant_ip_session(ip, now_unix(), state.config().general.session_minutes);
    }
    AuthReply::ok("admin_done")
}

/// Sets a new password for an existing account (operator action).
pub fn admin_set_password(state: &AuthState, target_lc: &str, new_password: &str) -> AuthReply {
    let config = state.config();

    let Some(mut record) = state.with_store(|store| store.get_by_username(target_lc).cloned())
    else {
        return AuthReply::fail("admin_unknown_account");
    };

    if let Err(error) = security::validate_password(
        new_password,
        &record.username,
        config.general.min_password_length,
        config.general.max_password_length,
    ) {
        return error.into();
    }

    match security::hash_password(state.hasher(), new_password) {
        Ok(hash) => record.password_hash = hash,
        Err(error) => return error.into(),
    }
    record.login_failures = 0;
    // Lockouts are keyed by UUID, so grab it before the record is moved.
    let uuid = record.uuid.clone();

    if state.with_store(|store| store.update(record)).is_err() {
        return AuthReply::fail("internal_error");
    }

    state.clear_lockout(&uuid);
    AuthReply::ok("admin_done")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_renders_placeholders() {
        let config = Config::default();
        let reply = AuthReply::with("password_too_short", vec![("min", "8".into())]);
        assert_eq!(reply.render(&config, "id"), "Password minimal 8 karakter.");
        assert_eq!(
            reply.render(&config, "en_us"),
            "Password must be at least 8 characters."
        );
    }

    #[test]
    fn reply_without_vars_renders_configured_message() {
        let config = Config::default();
        assert_eq!(
            AuthReply::ok("login_success").render(&config, "id"),
            "Login berhasil. Selamat bermain!"
        );
        // Unknown locales fall back to English.
        assert_eq!(
            AuthReply::ok("login_success").render(&config, "de_de"),
            "Login successful. Have fun!"
        );
    }

    #[test]
    fn password_errors_map_to_message_keys() {
        let reply: AuthReply = PasswordError::SameAsUsername.into();
        assert_eq!(reply.key, "password_is_username");

        let reply: AuthReply = PasswordError::TooShort { min: 6 }.into();
        assert_eq!(reply.key, "password_too_short");
        assert_eq!(reply.vars, vec![("min", "6".to_string())]);
    }

    #[test]
    fn hash_errors_never_leak_details() {
        let reply: AuthReply = PasswordError::Hash("secret internal detail".into()).into();
        assert_eq!(reply.key, "internal_error");
    }

    #[test]
    fn login_failure_message_does_not_reveal_account_existence() {
        let config = Config::default();
        for locale in ["en", "id", "de_de"] {
            assert_eq!(
                AuthReply::fail("login_failed").render(&config, locale),
                AuthReply::fail("not_registered").render(&config, locale),
                "a wrong password and a missing account must be indistinguishable ({locale})"
            );
        }
    }

    // --- premium decision table -------------------------------------------

    use crate::config::Premium;

    fn enabled_premium() -> Premium {
        Premium {
            enabled: true,
            ..Premium::default()
        }
    }

    fn enabled_config() -> Config {
        Config {
            premium: enabled_premium(),
            ..Config::default()
        }
    }

    /// Unique per call: tests run in parallel and must not share a directory.
    fn temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let mut path = std::env::temp_dir();
        path.push(format!(
            "pmcauth-auth-{}-{name}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn linked_record(connection_uuid: &str, premium_uuid: &str) -> UserRecord {
        let mut record = UserRecord::new(
            1,
            "Notch",
            connection_uuid,
            "hash".into(),
            "203.0.113.7",
            1000,
        );
        record.link_premium(premium_uuid, 1000);
        record
    }

    #[test]
    fn disabled_premium_never_auto_logs_in() {
        // `Premium::default()` is the shipped state: enabled = false.
        let premium = Premium::default();
        let record = linked_record("uuid-1", "uuid-1");
        assert_eq!(
            autologin_decision(&premium, PremiumAnchor::OnlineMode, "uuid-1", Some(&record)),
            PremiumDecision::PasswordFlow(PasswordFlowReason::Disabled)
        );
    }

    #[test]
    fn unregistered_player_never_auto_logs_in() {
        assert_eq!(
            autologin_decision(
                &enabled_premium(),
                PremiumAnchor::OnlineMode,
                "uuid-1",
                None
            ),
            PremiumDecision::PasswordFlow(PasswordFlowReason::NotRegistered)
        );
    }

    #[test]
    fn cracked_account_never_auto_logs_in() {
        let record = UserRecord::new(1, "Notch", "uuid-1", "hash".into(), "ip", 1000);
        assert_eq!(
            autologin_decision(
                &enabled_premium(),
                PremiumAnchor::OnlineMode,
                "uuid-1",
                Some(&record)
            ),
            PremiumDecision::PasswordFlow(PasswordFlowReason::NotLinked)
        );
    }

    #[test]
    fn uuid_mismatch_never_auto_logs_in() {
        // The offline case: the connection UUID is sha256(name), so it can only
        // equal the stored premium UUID when the connection really was verified.
        let record = linked_record("offline-uuid", "mojang-uuid");
        assert_eq!(
            autologin_decision(
                &enabled_premium(),
                PremiumAnchor::ForwardedProfile,
                "offline-uuid",
                Some(&record)
            ),
            PremiumDecision::PasswordFlow(PasswordFlowReason::UuidMismatch)
        );
    }

    #[test]
    fn missing_anchor_never_auto_logs_in() {
        // UUID matches, but nothing proves the connection was authenticated.
        let record = linked_record("uuid-1", "uuid-1");
        assert_eq!(
            autologin_decision(
                &enabled_premium(),
                PremiumAnchor::None,
                "uuid-1",
                Some(&record)
            ),
            PremiumDecision::PasswordFlow(PasswordFlowReason::NoAnchor)
        );
    }

    #[test]
    fn auto_login_requires_every_condition() {
        let record = linked_record("uuid-1", "uuid-1");
        assert_eq!(
            autologin_decision(
                &enabled_premium(),
                PremiumAnchor::OnlineMode,
                "uuid-1",
                Some(&record)
            ),
            PremiumDecision::AutoLogin {
                anchor: PremiumAnchor::OnlineMode
            }
        );
        assert_eq!(
            autologin_decision(
                &enabled_premium(),
                PremiumAnchor::ForwardedProfile,
                "uuid-1",
                Some(&record)
            ),
            PremiumDecision::AutoLogin {
                anchor: PremiumAnchor::ForwardedProfile
            }
        );
    }

    #[test]
    fn account_created_in_offline_mode_can_link_after_a_proxy_is_installed() {
        // The upgrade path that matters: the row is keyed by the offline UUID, the
        // proxy connection presents a Mojang UUID, so a UUID-only lookup would
        // answer "not registered" and the player could never link.
        let dir = temp_dir("premium-upgrade");
        let store = crate::storage::FileStore::open(&dir.join("users.json")).expect("store");
        let state = AuthState::new(enabled_config(), store);

        state
            .with_store(|store| {
                store.insert(UserRecord::new(
                    0,
                    "Notch",
                    "offline-uuid",
                    "hash".to_string(),
                    "ip",
                    1000,
                ))
            })
            .expect("insert");
        state.set_authenticated("mojang-uuid");

        let reply = premium_link(
            &state,
            "mojang-uuid",
            "Notch",
            PremiumAnchor::ForwardedProfile,
            true,
        );
        assert_eq!(reply.key, "premium_link_success");

        let record = state
            .with_store(|store| store.get_by_username("notch").cloned())
            .expect("record");
        // Bound to the Mojang UUID, so the next join matches.
        assert_eq!(record.active_premium_uuid(), Some("mojang-uuid"));
        // The row itself is not moved, so the offline password flow still resolves.
        assert_eq!(record.uuid, "offline-uuid");
    }

    #[test]
    fn uuid_comparison_is_case_insensitive() {
        // Pumpkin reports lowercase UUIDs; a hand-edited uppercase record must
        // still match instead of silently locking the owner out.
        let record = linked_record("uuid-1", "069A79F4-44E9-4726-A5BE-FCA90E38A366");
        assert!(matches!(
            autologin_decision(
                &enabled_premium(),
                PremiumAnchor::OnlineMode,
                "069a79f4-44e9-4726-a5be-fca90e38a366",
                Some(&record)
            ),
            PremiumDecision::AutoLogin { .. }
        ));
    }

    // --- link gating: the misconfiguration fail-safe ----------------------

    #[test]
    fn direct_offline_server_with_forwarded_trust_cannot_link() {
        // The scenario that must never grant anything: no proxy, no online mode,
        // trust_forwarded_profile = true, and therefore no textures property.
        let premium = Premium {
            enabled: true,
            trust_online_mode: false,
            trust_forwarded_profile: true,
            ..Premium::default()
        };

        // No anchor at all: refused.
        assert!(!can_link(&premium, PremiumAnchor::None, false));
        // An anchor is claimed but the profile carries no textures: still refused,
        // because nothing upstream actually authenticated this connection.
        assert!(!can_link(&premium, PremiumAnchor::ForwardedProfile, false));
        // Only a forwarded profile that really brought textures may link.
        assert!(can_link(&premium, PremiumAnchor::ForwardedProfile, true));
    }

    #[test]
    fn online_mode_anchor_can_link_without_textures() {
        // Online mode already proved ownership; a skinless profile is fine.
        assert!(can_link(
            &enabled_premium(),
            PremiumAnchor::OnlineMode,
            false
        ));
    }

    #[test]
    fn disabled_premium_cannot_link_even_with_a_perfect_anchor() {
        assert!(!can_link(
            &Premium::default(),
            PremiumAnchor::OnlineMode,
            true
        ));
    }

    #[test]
    fn textures_requirement_can_be_relaxed_but_an_anchor_is_still_mandatory() {
        let relaxed = Premium {
            enabled: true,
            trust_online_mode: false,
            trust_forwarded_profile: true,
            link_requires_textures: false,
            ..Premium::default()
        };
        assert!(can_link(&relaxed, PremiumAnchor::ForwardedProfile, false));
        assert!(!can_link(&relaxed, PremiumAnchor::None, true));
    }
}
