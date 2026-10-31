//! Plugin configuration loaded from `config.toml` inside the plugin data folder.
//!
//! Everything tunable lives here so operators never need to recompile: timeouts,
//! limits, Argon2 cost and every player-facing message.

use std::collections::BTreeMap;
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
    pub messages: BTreeMap<String, String>,
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
            messages: default_messages(),
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
        let mut config: Config = toml::from_str(&raw).map_err(|e| ConfigError::Parse(e.to_string()))?;

        // Operators legitimately delete message keys; merge the defaults back in
        // instead of failing the whole load.
        for (key, value) in default_messages() {
            config.messages.entry(key).or_insert(value);
        }

        config.general.sanitize();
        config.argon2.sanitize();
        Ok(config)
    }

    pub fn database_path(&self, dir: &Path) -> PathBuf {
        dir.join(&self.general.database_file)
    }

    /// Fetches a message, falling back to the key itself so nothing panics on a
    /// typo in the config.
    pub fn message<'a>(&'a self, key: &'a str) -> &'a str {
        self.messages.get(key).map_or(key, String::as_str)
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

fn default_messages() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (key, value) in DEFAULT_MESSAGES {
        map.insert((*key).to_string(), (*value).to_string());
    }
    map
}

/// Fallback messages used when the config file predates a key.
const DEFAULT_MESSAGES: &[(&str, &str)] = &[
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
        let config: Config = toml::from_str(DEFAULT_CONFIG).expect("default config must parse");
        assert_eq!(config.general.database_file, "users.json");
        assert!(!config.messages.is_empty());
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
        assert_eq!(config.message("does_not_exist"), "does_not_exist");
    }
}
