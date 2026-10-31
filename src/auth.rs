//! Authentication logic.
//!
//! Deliberately free of Pumpkin API calls: everything here takes plain data and
//! returns an [`AuthReply`]. That keeps the rules testable on the host and makes
//! the command layer a thin translation shell.

use crate::config::Config;
use crate::security::{self, PasswordError};
use crate::state::{AuthState, now_unix};
use crate::storage::{UserRecord, lowercase};

/// A rendered-later message: a config key plus placeholder values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthReply {
    pub key: &'static str,
    pub vars: Vec<(&'static str, String)>,
}

impl AuthReply {
    pub fn ok(key: &'static str) -> Self {
        Self { key, vars: Vec::new() }
    }

    pub fn fail(key: &'static str) -> Self {
        Self { key, vars: Vec::new() }
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

    // Cheap existence check before spending Argon2 time.
    let taken = state.with_store(|store| {
        store.get_by_uuid(uuid).is_some() || store.get_by_username(&name_key).is_some()
    });
    if taken {
        return AuthReply::fail("already_registered");
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
    state.grant_ip_session(ip, now, config.general.session_minutes);

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
        return AuthReply::with("kicked_bruteforce", vec![("seconds", remaining.to_string())]);
    }

    let name_key = lowercase(username);
    let record = state.with_store(|store| {
        store
            .get_by_uuid(uuid)
            .or_else(|| store.get_by_username(&name_key))
            .cloned()
    });

    let Some(record) = record else {
        // Burn the same Argon2 work as a real check so response time does not
        // reveal whether the account exists.
        if let Some(dummy) = state.dummy_hash() {
            security::verify_dummy(state.hasher(), password, dummy);
        }
        return AuthReply::fail("not_registered");
    };

    if !security::verify_password(state.hasher(), password, &record.password_hash) {
        return record_failure(state, &config, uuid, record);
    }

    let mut record = record;
    record.last_ip = ip.to_string();
    record.last_login = now;
    record.login_failures = 0;
    let _ = state.with_store(|store| store.update(record));

    state.clear_lockout(uuid);
    state.remove_session(uuid);
    state.set_authenticated(uuid);
    state.grant_ip_session(ip, now, config.general.session_minutes);

    AuthReply::ok("login_success")
}

/// Counts a failed attempt and locks the account out when the limit is reached.
fn record_failure(state: &AuthState, config: &Config, uuid: &str, mut record: UserRecord) -> AuthReply {
    record.login_failures = record.login_failures.saturating_add(1);
    let failures = record.login_failures;
    let _ = state.with_store(|store| store.update(record));

    if failures >= config.general.max_login_attempts {
        state.lock(uuid, now_unix(), config.general.lockout_seconds);
    }

    AuthReply::fail("login_failed")
}

/// Logs an authenticated player out and forgets their IP session.
pub fn logout(state: &AuthState, uuid: &str, ip: &str) -> AuthReply {
    if !state.clear_authenticated(uuid) {
        return AuthReply::fail("not_logged_in");
    }
    state.revoke_ip_session(ip);
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
    let exists = state.with_store(|store| store.get_by_uuid(uuid).is_some());
    if !exists {
        return AuthReply::fail("admin_unknown_account");
    }

    state.remove_session(uuid);
    state.clear_lockout(uuid);
    state.set_authenticated(uuid);
    state.grant_ip_session(ip, now_unix(), state.config().general.session_minutes);
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
}
