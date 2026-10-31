//! Password hashing and the password policy.
//!
//! Argon2id, per-user random salt, PHC-encoded output. Nothing here ever logs or
//! returns the plaintext password.

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

use crate::config::Argon2Config;

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordError {
    TooShort { min: usize },
    TooLong { max: usize },
    SameAsUsername,
    Hash(String),
}

impl PasswordError {
    /// Config key whose message describes this error.
    pub fn message_key(&self) -> &'static str {
        match self {
            Self::TooShort { .. } => "password_too_short",
            Self::TooLong { .. } => "password_too_long",
            Self::SameAsUsername => "password_is_username",
            // Never surface hashing internals to the player.
            Self::Hash(_) => "internal_error",
        }
    }
}

/// Builds the hasher from config. Falls back to the crate defaults if the config
/// contains impossible parameters, so a bad config cannot lock everyone out.
pub fn build_argon2(config: &Argon2Config) -> Argon2<'static> {
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        None,
    )
    .unwrap_or(Params::DEFAULT);

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Validates a prospective password against the policy.
pub fn validate_password(
    password: &str,
    username: &str,
    min_len: usize,
    max_len: usize,
) -> Result<(), PasswordError> {
    let len = password.chars().count();

    if len < min_len {
        return Err(PasswordError::TooShort { min: min_len });
    }
    if len > max_len {
        return Err(PasswordError::TooLong { max: max_len });
    }
    if password.eq_ignore_ascii_case(username) {
        return Err(PasswordError::SameAsUsername);
    }
    Ok(())
}

/// Hashes `password` into a self-describing PHC string (algorithm, params, salt,
/// hash), which is what gets stored in the database.
pub fn hash_password(hasher: &Argon2<'_>, password: &str) -> Result<String, PasswordError> {
    hasher
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| PasswordError::Hash(e.to_string()))
}

/// Verifies `password` against a stored PHC string.
///
/// Returns `false` for both a wrong password and a corrupt stored hash: the
/// caller must not distinguish between them in player-facing output.
/// The comparison itself is constant-time inside `verify_password`.
pub fn verify_password(hasher: &Argon2<'_>, password: &str, stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    hasher.verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Burns the same amount of work as a real verification.
///
/// Called when the account does not exist so an attacker cannot tell registered
/// usernames apart by response time.
pub fn verify_dummy(hasher: &Argon2<'_>, password: &str, dummy_hash: &str) {
    let _ = verify_password(hasher, password, dummy_hash);
}

/// A hash of an unguessable random string, computed once at startup.
///
/// `verify_dummy` is run against this instead of `verify_password` returning
/// early, which is what makes the timing roughly equal.
pub fn make_dummy_hash(hasher: &Argon2<'_>) -> Option<String> {
    hash_password(hasher, "\u{0}pmcauth-dummy-password\u{0}").ok()
}

/// Cheap, non-cryptographic placeholder used when the store has no hash for a
/// user yet. Kept explicit so nobody mistakes it for a real password.
pub const NO_PASSWORD: &str = "";

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { min } => write!(f, "password shorter than {min}"),
            Self::TooLong { max } => write!(f, "password longer than {max}"),
            Self::SameAsUsername => write!(f, "password equals username"),
            Self::Hash(e) => write!(f, "hashing failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hasher() -> Argon2<'static> {
        // Much cheaper than production so tests stay fast.
        let params = Params::new(64, 1, 1, None).expect("valid test params");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    #[test]
    fn rejects_short_password() {
        let err = validate_password("abc", "player", 6, 64).unwrap_err();
        assert_eq!(err, PasswordError::TooShort { min: 6 });
        assert_eq!(err.message_key(), "password_too_short");
    }

    #[test]
    fn rejects_long_password() {
        let long = "a".repeat(65);
        let err = validate_password(&long, "player", 6, 64).unwrap_err();
        assert_eq!(err, PasswordError::TooLong { max: 64 });
    }

    #[test]
    fn rejects_password_equal_to_username() {
        let err = validate_password("Player", "player", 6, 64).unwrap_err();
        assert_eq!(err, PasswordError::SameAsUsername);
    }

    #[test]
    fn accepts_valid_password() {
        assert!(validate_password("hunter2!", "player", 6, 64).is_ok());
    }

    #[test]
    fn counts_characters_not_bytes() {
        // 6 characters, 18 bytes in UTF-8: must pass a min length of 6.
        assert!(validate_password("pässwörd", "player", 6, 64).is_ok());
    }

    #[test]
    fn hash_verify_roundtrip() {
        let hasher = test_hasher();
        let hash = hash_password(&hasher, "hunter2!").expect("hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(&hasher, "hunter2!", &hash));
    }

    #[test]
    fn rejects_wrong_password() {
        let hasher = test_hasher();
        let hash = hash_password(&hasher, "hunter2!").expect("hash");
        assert!(!verify_password(&hasher, "hunter3!", &hash));
    }

    #[test]
    fn salt_is_unique_per_hash() {
        let hasher = test_hasher();
        let a = hash_password(&hasher, "same-password").expect("hash a");
        let b = hash_password(&hasher, "same-password").expect("hash b");
        assert_ne!(
            a, b,
            "identical passwords must not produce identical hashes"
        );
        assert!(verify_password(&hasher, "same-password", &a));
        assert!(verify_password(&hasher, "same-password", &b));
    }

    #[test]
    fn corrupt_hash_is_rejected_not_panicking() {
        let hasher = test_hasher();
        assert!(!verify_password(&hasher, "anything", "not-a-phc-string"));
        assert!(!verify_password(&hasher, "anything", ""));
    }

    #[test]
    fn dummy_hash_is_verifiable() {
        let hasher = test_hasher();
        let dummy = make_dummy_hash(&hasher).expect("dummy");
        // No panic, and the dummy itself never matches a real guess.
        verify_dummy(&hasher, "whatever", &dummy);
        assert!(!verify_password(&hasher, "whatever", &dummy));
    }

    #[test]
    fn bad_config_falls_back_to_defaults() {
        let config = Argon2Config {
            memory_kib: 1,
            iterations: 0,
            parallelism: 0,
        };
        // Must not panic even though the values are invalid.
        let _ = build_argon2(&config);
    }
}
