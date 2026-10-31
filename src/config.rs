//! Plugin configuration loaded from `config.toml` inside the plugin data folder.
//!
//! Everything tunable lives here so operators never need to recompile: timeouts,
//! limits, Argon2 cost and every player-facing message.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Default `config.toml` contents written on first run.
const DEFAULT_CONFIG: &str = include_str!("../config.default.toml");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub argon2: Argon2Config,
    /// Messages keyed by language, e.g. `[messages.en]` / `[messages.id]`.
    ///
    /// Written in this nested form on first run. A config written by an older
    /// version has a flat `[messages]` table; that is still accepted and its
    /// entries become the English messages, so upgrading keeps the operator's
    /// wording instead of failing the load.
    #[serde(deserialize_with = "deserialize_messages")]
    pub messages: HashMap<String, BTreeMap<String, String>>,
}

/// Accepts both message layouts:
///
/// - current: `[messages.en]` / `[messages.id]` -- a table of tables
/// - legacy:  `[messages]` with plain strings, read as English
fn deserialize_messages<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, BTreeMap<String, String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let raw = toml::value::Table::deserialize(deserializer)?;

    // Legacy flat table: every value is a string.
    if raw.values().all(toml::Value::is_str) {
        let messages = raw
            .into_iter()
            .map(|(key, value)| {
                value
                    .as_str()
                    .map(|text| (key, text.to_string()))
                    .ok_or_else(|| D::Error::custom("expected a string message"))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        return Ok(HashMap::from([(DEFAULT_LANGUAGE.to_string(), messages)]));
    }

    raw.into_iter()
        .map(|(language, value)| {
            let table = value
                .as_table()
                .ok_or_else(|| D::Error::custom("expected a table of messages per language"))?;

            let messages = table
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|text| (key.clone(), text.to_string()))
                        .ok_or_else(|| D::Error::custom("message must be a string"))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;

            Ok((language, messages))
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    /// User database file name, relative to the plugin data folder.
    pub database_file: String,
    /// Seconds a player has to authenticate before being kicked.
    pub login_timeout_seconds: u64,
    /// Seconds between "please log in" reminders. 0 disables reminders.
    pub reminder_interval_seconds: u64,
    /// Minutes an IP stays authenticated. 0 disables IP sessions.
    pub session_minutes: u64,
    pub min_password_length: usize,
    pub max_password_length: usize,
    /// Failed logins before a temporary lockout.
    pub max_login_attempts: u32,
    /// How long the lockout lasts.
    pub lockout_seconds: u64,
    /// Whether a timeout kicks the player or only re-prompts them.
    pub kick_on_timeout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Argon2Config {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for General {
    fn default() -> Self {
        Self {
            database_file: "users.json".to_string(),
            login_timeout_seconds: 60,
            reminder_interval_seconds: 10,
            session_minutes: 0,
            min_password_length: 6,
            max_password_length: 64,
            max_login_attempts: 3,
            lockout_seconds: 300,
            kick_on_timeout: true,
        }
    }
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            // Deliberately modest: this runs on the server's main thread inside a
            // single-threaded WASM sandbox, and login latency is felt by the player.
            memory_kib: 8 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: General::default(),
            argon2: Argon2Config::default(),
            messages: builtin_messages(),
        }
    }
}

impl Config {
    /// Loads `config.toml` from `dir`, writing the default file first if missing.
    ///
    /// A malformed file is not fatal: the error is returned so the caller can log
    /// it, and the caller decides whether to fall back to defaults.
    pub fn load(dir: &Path) -> Result<Self, ConfigError> {
        let path = dir.join("config.toml");

        if !path.exists() {
            fs::write(&path, DEFAULT_CONFIG).map_err(|e| ConfigError::Io(e.to_string()))?;
        }

        let raw = fs::read_to_string(&path).map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::parse(&raw)
    }

    /// Parses config TOML, merging built-in messages back in per language.
    ///
    /// Operators legitimately delete message keys; a missing key must not fail
    /// the whole load, and must not silently vanish either.
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let mut config: Config =
            toml::from_str(raw).map_err(|e| ConfigError::Parse(e.to_string()))?;

        // Fill only the gaps so the operator's wording wins over the built-in.
        for (language, messages) in builtin_messages() {
            let entry = config.messages.entry(language).or_default();
            for (key, value) in messages {
                entry.entry(key).or_insert(value);
            }
        }

        config.general.sanitize();
        config.argon2.sanitize();
        Ok(config)
    }

    pub fn database_path(&self, dir: &Path) -> PathBuf {
        dir.join(&self.general.database_file)
    }

    /// Fetches a message in the given client locale.
    ///
    /// Falls back to English, then to the key itself so a typo in the config
    /// never panics. `locale` is whatever the server reports, e.g. `id_id`,
    /// `en_US` or `id`.
    pub fn message<'a>(&'a self, key: &'a str, locale: &str) -> &'a str {
        let language = language_of(locale);

        self.messages
            .get(language)
            .and_then(|messages| messages.get(key))
            // English is the documented default and is always built in.
            .or_else(|| {
                self.messages
                    .get(DEFAULT_LANGUAGE)
                    .and_then(|messages| messages.get(key))
            })
            .map_or(key, String::as_str)
    }
}

/// Language used when the client locale is unknown or unsupported.
pub const DEFAULT_LANGUAGE: &str = "en";

/// Reduces a client locale to a supported language code.
///
/// `id_id`, `id-ID` and `id` all mean Indonesian; anything unrecognised falls
/// back to [`DEFAULT_LANGUAGE`].
pub fn language_of(locale: &str) -> &'static str {
    let tag = locale
        .split(['_', '-'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();

    match tag.as_str() {
        "id" => "id",
        _ => DEFAULT_LANGUAGE,
    }
}

impl General {
    fn sanitize(&mut self) {
        self.min_password_length = self.min_password_length.max(1);
        self.max_password_length = self.max_password_length.max(self.min_password_length);
        self.max_login_attempts = self.max_login_attempts.max(1);
        if self.database_file.trim().is_empty() {
            self.database_file = "users.json".to_string();
        }
    }
}

impl Argon2Config {
    fn sanitize(&mut self) {
        // Argon2 requires m_cost >= 8 * p_cost and p_cost >= 1.
        self.parallelism = self.parallelism.clamp(1, 255);
        self.iterations = self.iterations.max(1);
        self.memory_kib = self.memory_kib.max(8 * self.parallelism);
    }
}

fn builtin_messages() -> HashMap<String, BTreeMap<String, String>> {
    let mut languages = HashMap::new();
    for (language, messages) in BUILTIN_MESSAGES {
        let mut map = BTreeMap::new();
        for (key, value) in *messages {
            map.insert((*key).to_string(), (*value).to_string());
        }
        languages.insert((*language).to_string(), map);
    }
    languages
}

/// Messages compiled into the plugin, per language.
///
/// English is the default; Indonesian is built in too. Both are always merged
/// into the loaded config, so a missing or deleted key still resolves.
const BUILTIN_MESSAGES: &[(&str, &[(&str, &str)])] = &[
    (DEFAULT_LANGUAGE, MESSAGES_EN),
    ("id", MESSAGES_ID),
];

const MESSAGES_EN: &[(&str, &str)] = &[
    ("register_prompt", "Please /register <password> <repeat_password>"),
    ("login_prompt", "Please /login <password>"),
    ("register_success", "Registration successful. Have fun!"),
    ("login_success", "Login successful. Have fun!"),
    // Deliberately identical to not_registered: never reveal whether an account exists.
    ("login_failed", "Login failed."),
    ("not_registered", "Login failed."),
    ("already_registered", "That account is already registered."),
    ("already_logged_in", "You are already logged in."),
    ("not_logged_in", "You are not logged in."),
    ("password_too_short", "Password must be at least {min} characters."),
    ("password_too_long", "Password must be at most {max} characters."),
    ("password_mismatch", "Password confirmation does not match."),
    ("password_is_username", "Password must not be your username."),
    ("logout_success", "You have been logged out."),
    ("change_success", "Password changed successfully."),
    ("kicked_timeout", "Login timed out."),
    ("kicked_bruteforce", "Too many login attempts. Try again later."),
    ("reminder", "You are not logged in. {seconds} seconds left."),
    ("deny_generic", "Please log in before doing that."),
    ("admin_usage", "Usage: /authadmin <unregister|forcelogin|setpassword> <player> [password]"),
    ("admin_player_offline", "Player not found."),
    ("admin_unknown_account", "Account not found."),
    ("admin_done", "Done."),
    ("internal_error", "Internal error. Contact an admin."),
];

const MESSAGES_ID: &[(&str, &str)] = &[
    ("register_prompt", "Silakan /register <password> <ulangi_password>"),
    ("login_prompt", "Silakan /login <password>"),
    ("register_success", "Registrasi berhasil. Selamat bermain!"),
    ("login_success", "Login berhasil. Selamat bermain!"),
    ("login_failed", "Login gagal."),
    ("not_registered", "Login gagal."),
    ("already_registered", "Akun sudah terdaftar."),
    ("already_logged_in", "Kamu sudah login."),
    ("not_logged_in", "Kamu belum login."),
    ("password_too_short", "Password minimal {min} karakter."),
    ("password_too_long", "Password maksimal {max} karakter."),
    ("password_mismatch", "Konfirmasi password tidak cocok."),
    ("password_is_username", "Password tidak boleh sama dengan nama akun."),
    ("logout_success", "Kamu telah logout."),
    ("change_success", "Password berhasil diubah."),
    ("kicked_timeout", "Waktu login habis."),
    ("kicked_bruteforce", "Terlalu banyak percobaan login. Coba lagi nanti."),
    ("reminder", "Kamu belum login. Sisa waktu {seconds} detik."),
    ("deny_generic", "Login dulu sebelum melakukan itu."),
    ("admin_usage", "Usage: /authadmin <unregister|forcelogin|setpassword> <player> [password]"),
    ("admin_player_offline", "Player tidak ditemukan."),
    ("admin_unknown_account", "Akun tidak ditemukan."),
    ("admin_done", "Selesai."),
    ("internal_error", "Terjadi kesalahan internal. Hubungi admin."),
];

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "config io error: {e}"),
            Self::Parse(e) => write!(f, "config parse error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let config = Config::default();
        assert!(config.general.min_password_length >= 1);
        assert!(config.general.max_password_length >= config.general.min_password_length);
        assert!(config.general.max_login_attempts >= 1);
        assert!(config.argon2.memory_kib >= 8 * config.argon2.parallelism);
    }

    #[test]
    fn default_toml_parses() {
        let config = Config::parse(DEFAULT_CONFIG).expect("default config must parse");
        assert_eq!(config.general.database_file, "users.json");
        assert!(config.messages.contains_key("en"));
        assert!(config.messages.contains_key("id"));
    }

    #[test]
    fn sanitize_clamps_bad_values() {
        let mut general = General {
            min_password_length: 0,
            max_password_length: 0,
            max_login_attempts: 0,
            database_file: "  ".into(),
            ..General::default()
        };
        general.sanitize();
        assert_eq!(general.min_password_length, 1);
        assert_eq!(general.max_password_length, 1);
        assert_eq!(general.max_login_attempts, 1);
        assert_eq!(general.database_file, "users.json");
    }

    #[test]
    fn missing_message_falls_back_to_key() {
        let config = Config::default();
        assert_eq!(config.message("does_not_exist", "en"), "does_not_exist");
    }

    #[test]
    fn locales_resolve_indonesian_and_fall_back_to_english() {
        let config = Config::default();

        assert_eq!(language_of("id"), "id");
        assert_eq!(language_of("id_id"), "id");
        assert_eq!(language_of("id-ID"), "id");
        assert_eq!(language_of("ID_ID"), "id");

        // Unsupported or empty locales use the English default.
        assert_eq!(language_of("en_us"), "en");
        assert_eq!(language_of("de_de"), "en");
        assert_eq!(language_of(""), "en");

        assert_eq!(config.message("login_success", "id_id"), "Login berhasil. Selamat bermain!");
        assert_eq!(config.message("login_success", "en_us"), "Login successful. Have fun!");
        assert_eq!(config.message("login_success", "de_de"), "Login successful. Have fun!");
    }

    #[test]
    fn every_builtin_language_defines_every_key() {
        let config = Config::default();
        let english = config.messages.get(DEFAULT_LANGUAGE).expect("english built in");

        for language in config.messages.keys() {
            let messages = &config.messages[language];
            for key in english.keys() {
                assert!(
                    messages.contains_key(key),
                    "language {language} is missing message {key}"
                );
            }
        }
    }

    #[test]
    fn legacy_flat_messages_table_is_read_as_english() {
        // What older versions wrote: one flat table of strings.
        let raw = r#"
            [messages]
            login_success = "Login berhasil versi lama"
            login_failed = "Gagal versi lama"
        "#;
        let config = Config::parse(raw).expect("legacy config must still load");

        assert_eq!(
            config.message("login_success", "en"),
            "Login berhasil versi lama",
            "an existing install must keep its own wording"
        );
        // A player asking for Indonesian still gets the built-in translation,
        // not the operator's English wording.
        assert_eq!(
            config.message("login_success", "id"),
            "Login berhasil. Selamat bermain!"
        );
        // Keys the legacy file did not have still resolve.
        assert_eq!(config.message("reminder", "en"), "You are not logged in. {seconds} seconds left.");
    }

    #[test]
    fn operator_overrides_win_and_missing_keys_are_merged() {
        // Only one key is overridden; everything else must come from the defaults.
        let raw = r#"
            [messages.en]
            login_success = "Custom!"
        "#;
        let config = Config::parse(raw).expect("parse");

        assert_eq!(config.message("login_success", "en"), "Custom!");
        assert_eq!(
            config.message("login_failed", "en"),
            "Login failed.",
            "keys the operator deleted are merged back in"
        );
        assert_eq!(
            config.message("login_success", "id"),
            "Login berhasil. Selamat bermain!",
            "the other language is untouched"
        );
    }
}
