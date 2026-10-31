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

/// Version of the config layout the plugin currently understands.
///
/// Bump this whenever a key is added to [`DEFAULT_CONFIG`] so existing files get
/// it merged in on the next start. A file without `config_version` is treated as
/// version 0, which is every config written before 0.3.1.
pub const CONFIG_VERSION: u32 = 1;

/// Key holding the config version. It is merged silently when missing.
const VERSION_KEY: &str = "config_version";

/// Marker comment that precedes a key operators should not delete.
///
/// When such a key is missing, the migration copies the marker *and* the key, so
/// the regenerated section still explains itself.
const AUTO_MARKER: &str = "@pmcauto";

/// What a load did to the file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigMigration {
    /// The file was already current. Nothing was written.
    UpToDate,
    /// Keys were added (and/or the version moved forward). The file was rewritten.
    Written { from: u32, to: u32, added: usize },
    /// The file did not parse. It was kept as `config.toml.broken` and replaced
    /// by a fresh default, so the server still runs on known settings.
    ReplacedBroken { detail: String },
}

impl ConfigMigration {
    /// Whether the file on disk changed.
    pub const fn wrote(&self) -> bool {
        matches!(self, Self::Written { .. } | Self::ReplacedBroken { .. })
    }
}

/// Why a load could not produce a config at all.
///
/// A *broken* file is reported through [`ConfigMigration::ReplacedBroken`]
/// instead, because it still yields a usable config.
#[derive(Debug, Clone)]
pub enum LoadError {
    Io(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "config io error: {e}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Version of the on-disk layout this file was written with.
    ///
    /// Serialised so a rewrite keeps it. Migration compares the *document* in
    /// [`Config::migrate`], not this field, because a missing key must be
    /// distinguishable from a hand-written zero.
    pub config_version: u32,
    pub general: General,
    pub argon2: Argon2Config,
    /// Premium (Mojang-authenticated) login. Disabled by default.
    pub premium: Premium,
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
    /// What a failed or unknown-name `/login` attempt counts against.
    ///
    /// `"uuid"` (default) is correct on every deployment. `"ip"` is stronger
    /// but only valid behind Velocity/Vine-style forwarding; behind BungeeCord
    /// every player shares one IP and the whole server would be locked out.
    pub rate_limit_scope: RateLimitScope,
}

/// Scope of the unknown-name / failed-login failure counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitScope {
    /// Count per player connection. Safe everywhere.
    #[default]
    Uuid,
    /// Count per client IP, in addition to per UUID. Topology-dependent.
    Ip,
}

/// Premium login settings.
///
/// This feature never talks to Mojang. It only trusts a profile when the server,
/// or a proxy the operator vouched for, already authenticated that connection.
/// There is deliberately no timeout, retry, cache or rate-limit setting: those
/// exist to protect an HTTP call this plugin does not make.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Premium {
    /// Master switch. `false` means the plugin behaves exactly as it did in 0.2.x.
    pub enabled: bool,
    /// Trust a profile the server itself authenticated with Mojang.
    ///
    /// Only has any effect when `networking.java.online_mode = true` in the
    /// server's own `pumpkin.toml`.
    pub trust_online_mode: bool,
    /// Trust a profile forwarded by an authenticating proxy.
    ///
    /// The plugin cannot read the proxy's state, so this is the operator's
    /// assertion. It is not sufficient on its own: the profile must also carry a
    /// `textures` property, which a bare offline server never produces.
    pub trust_forwarded_profile: bool,
    /// Require a player to run `/premium` once instead of linking on join.
    pub require_claim: bool,
    /// Refuse `/register` for a name already premium-linked in this database.
    pub block_linked_names: bool,
    /// Require the `textures` property when relying on a forwarded profile.
    ///
    /// Turning this off weakens the only evidence the plugin has. Leave it on.
    pub link_requires_textures: bool,
    /// Log the autologin decision for every join: link state, anchor and outcome.
    pub log_decisions: bool,
}

impl Default for Premium {
    fn default() -> Self {
        Self {
            // Off by default: a direct offline server must behave exactly as before.
            enabled: false,
            trust_online_mode: true,
            trust_forwarded_profile: false,
            require_claim: true,
            block_linked_names: true,
            link_requires_textures: true,
            log_decisions: false,
        }
    }
}

impl Premium {
    /// Normalises the settings and reports whether the feature had to be disabled.
    ///
    /// A premium feature with no trust anchor can never authenticate anyone, so it
    /// is turned off rather than left on to refuse every link in front of players.
    /// Returns `true` when `enabled` was forced to `false`.
    fn sanitize(&mut self) -> bool {
        if self.enabled && !self.trust_online_mode && !self.trust_forwarded_profile {
            self.enabled = false;
            return true;
        }
        false
    }

    /// Whether any trust anchor is enabled at all.
    pub const fn any_anchor_enabled(&self) -> bool {
        self.trust_online_mode || self.trust_forwarded_profile
    }
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
            rate_limit_scope: RateLimitScope::default(),
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
            config_version: 0,
            general: General::default(),
            argon2: Argon2Config::default(),
            premium: Premium::default(),
            messages: builtin_messages(),
        }
    }
}

impl Config {
    /// Loads `config.toml` from `dir`, migrating it forward when needed.
    ///
    /// The file is repaired in three cases, so the plugin never runs on settings
    /// nobody can see or edit:
    /// - missing -- written from [`DEFAULT_CONFIG`]
    /// - unparseable -- kept as `config.toml.broken`, then replaced
    /// - older than [`CONFIG_VERSION`], or missing keys that exist in the default
    ///   -- merged in place, keeping every value and comment already present
    ///
    /// The second element reports what happened, so the caller can log it.
    /// A broken file still yields a usable config: refusing to boot would take
    /// the whole server down over a typo.
    ///
    /// Idempotent. A current file that already has every key is only read.
    pub fn load(dir: &Path) -> Result<(Self, ConfigMigration), LoadError> {
        let path = dir.join("config.toml");

        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            // Missing file: write the default and treat it as brand new.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                write_default(&path)?;
                let raw = fs::read_to_string(&path).map_err(|e| LoadError::Io(e.to_string()))?;
                let config = Self::parse(&raw).map_err(|e| LoadError::Io(e.to_string()))?;
                return Ok((
                    config,
                    ConfigMigration::Written {
                        from: 0,
                        to: CONFIG_VERSION,
                        added: 0,
                    },
                ));
            }
            Err(e) => return Err(LoadError::Io(e.to_string())),
        };

        // Parse before touching anything. A document that does not parse is never
        // merged: a half-edited broken file is worse than a fresh, known-good one.
        let broken = match Self::parse(&raw) {
            Ok(config) => return Ok((config, Self::migrate(&path, &raw)?)),
            Err(error) => error.to_string(),
        };

        let _ = fs::rename(&path, dir.join("config.toml.broken"));
        write_default(&path)?;
        let raw = fs::read_to_string(&path).map_err(|e| LoadError::Io(e.to_string()))?;
        let config = Self::parse(&raw).map_err(|e| LoadError::Io(e.to_string()))?;
        Ok((config, ConfigMigration::ReplacedBroken { detail: broken }))
    }

    /// Merges the default into `raw`, writing only if something was actually added.
    ///
    /// Only missing keys are inserted. Values, ordering, whitespace and comments
    /// already in the file stay exactly as the operator wrote them, which is why
    /// this edits a `toml_edit` document instead of re-serialising [`Config`].
    ///
    /// Returns [`ConfigMigration::UpToDate`] without touching the disk when the
    /// file is already complete, so a normal start is a single read.
    pub fn migrate(path: &Path, raw: &str) -> Result<ConfigMigration, LoadError> {
        let mut document: toml_edit::DocumentMut = raw
            .parse()
            .map_err(|e: toml_edit::TomlError| LoadError::Io(e.to_string()))?;
        let default: toml_edit::DocumentMut = DEFAULT_CONFIG
            .parse()
            .map_err(|e: toml_edit::TomlError| LoadError::Io(e.to_string()))?;

        let from = document
            .get(VERSION_KEY)
            .and_then(toml_edit::Item::as_integer)
            // A hand-written negative version must not wrap to a huge number.
            .map_or(0, |v| u32::try_from(v).unwrap_or(0));

        let mut added = 0;
        fill_missing(document.as_table_mut(), default.as_table(), "", &mut added);

        // Stamp the version only after every key is actually present.
        if from < CONFIG_VERSION {
            document[VERSION_KEY] = toml_edit::value(i64::from(CONFIG_VERSION));
        }

        if added == 0 && from >= CONFIG_VERSION {
            return Ok(ConfigMigration::UpToDate);
        }

        write_atomic(path, document.to_string().as_bytes())?;
        Ok(ConfigMigration::Written {
            from,
            to: CONFIG_VERSION,
            added,
        })
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
        config.premium.sanitize();
        Ok(config)
    }

    /// Writes the default config to `<dir>/config.toml`.
    ///
    /// Used on first run, and to repair a deleted or unparseable file.
    pub fn write_default(dir: &Path) -> Result<(), LoadError> {
        fs::create_dir_all(dir).map_err(|e| LoadError::Io(e.to_string()))?;
        write_default(&dir.join("config.toml"))
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
const BUILTIN_MESSAGES: &[(&str, &[(&str, &str)])] =
    &[(DEFAULT_LANGUAGE, MESSAGES_EN), ("id", MESSAGES_ID)];

const MESSAGES_EN: &[(&str, &str)] = &[
    (
        "register_prompt",
        "Please /register <password> <repeat_password>",
    ),
    ("login_prompt", "Please /login <password>"),
    ("register_success", "Registration successful. Have fun!"),
    ("login_success", "Login successful. Have fun!"),
    // Deliberately identical to not_registered: never reveal whether an account exists.
    ("login_failed", "Login failed."),
    ("not_registered", "Login failed."),
    ("already_registered", "That account is already registered."),
    ("already_logged_in", "You are already logged in."),
    ("not_logged_in", "You are not logged in."),
    (
        "password_too_short",
        "Password must be at least {min} characters.",
    ),
    (
        "password_too_long",
        "Password must be at most {max} characters.",
    ),
    ("password_mismatch", "Password confirmation does not match."),
    (
        "password_is_username",
        "Password must not be your username.",
    ),
    ("logout_success", "You have been logged out."),
    ("change_success", "Password changed successfully."),
    ("kicked_timeout", "Login timed out."),
    (
        "kicked_bruteforce",
        "Too many login attempts. Try again later.",
    ),
    ("reminder", "You are not logged in. {seconds} seconds left."),
    ("deny_generic", "Please log in before doing that."),
    (
        "admin_usage",
        "Usage: /authadmin <unregister|forcelogin|setpassword|premium> <player> [password]",
    ),
    ("admin_player_offline", "Player not found."),
    ("admin_unknown_account", "Account not found."),
    ("admin_done", "Done."),
    ("internal_error", "Internal error. Contact an admin."),
    (
        "premium_login_success",
        "Premium login verified. Welcome back!",
    ),
    (
        "premium_status_linked",
        "Premium login is enabled for this account ({uuid}).",
    ),
    (
        "premium_status_not_linked",
        "Premium login is not enabled for this account.",
    ),
    (
        "premium_link_success",
        "Premium login enabled for this account.",
    ),
    (
        "premium_link_already",
        "Premium login is already enabled for this account.",
    ),
    (
        "premium_unlink_success",
        "Premium login disabled. Use /login from now on.",
    ),
    (
        "premium_unlink_not_linked",
        "Premium login is not enabled for this account.",
    ),
    (
        "premium_unavailable",
        "Premium login is not available on this server. Ask an admin.",
    ),
    (
        "premium_needs_profile",
        "Premium login needs a verified Minecraft profile. Join through the proxy and try again.",
    ),
    (
        "premium_name_blocked",
        "That name is reserved by a premium account.",
    ),
    (
        "premium_admin_requires_online",
        "The player must be online: premium login binds their current session UUID.",
    ),
];

const MESSAGES_ID: &[(&str, &str)] = &[
    (
        "register_prompt",
        "Silakan /register <password> <ulangi_password>",
    ),
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
    (
        "password_is_username",
        "Password tidak boleh sama dengan nama akun.",
    ),
    ("logout_success", "Kamu telah logout."),
    ("change_success", "Password berhasil diubah."),
    ("kicked_timeout", "Waktu login habis."),
    (
        "kicked_bruteforce",
        "Terlalu banyak percobaan login. Coba lagi nanti.",
    ),
    ("reminder", "Kamu belum login. Sisa waktu {seconds} detik."),
    ("deny_generic", "Login dulu sebelum melakukan itu."),
    (
        "admin_usage",
        "Usage: /authadmin <unregister|forcelogin|setpassword|premium> <player> [password]",
    ),
    ("admin_player_offline", "Player tidak ditemukan."),
    ("admin_unknown_account", "Akun tidak ditemukan."),
    ("admin_done", "Selesai."),
    (
        "internal_error",
        "Terjadi kesalahan internal. Hubungi admin.",
    ),
    (
        "premium_login_success",
        "Login premium terverifikasi. Selamat datang kembali!",
    ),
    (
        "premium_status_linked",
        "Login premium aktif untuk akun ini ({uuid}).",
    ),
    (
        "premium_status_not_linked",
        "Login premium tidak aktif untuk akun ini.",
    ),
    (
        "premium_link_success",
        "Login premium diaktifkan untuk akun ini.",
    ),
    (
        "premium_link_already",
        "Login premium sudah aktif untuk akun ini.",
    ),
    (
        "premium_unlink_success",
        "Login premium dimatikan. Mulai sekarang gunakan /login.",
    ),
    (
        "premium_unlink_not_linked",
        "Login premium tidak aktif untuk akun ini.",
    ),
    (
        "premium_unavailable",
        "Login premium tidak tersedia di server ini. Hubungi admin.",
    ),
    (
        "premium_needs_profile",
        "Login premium butuh profil Minecraft terverifikasi. Masuk lewat proxy lalu coba lagi.",
    ),
    (
        "premium_name_blocked",
        "Nama itu sudah dipakai akun premium.",
    ),
    (
        "premium_admin_requires_online",
        "Player harus online: login premium mengikat UUID sesi yang sedang berjalan.",
    ),
];

/// Recursively copies keys that `target` is missing out of `default`.
///
/// Nested tables are walked, so a `[premium]` block added in a later version
/// lands inside the existing table instead of as a duplicate root key.
///
/// Every decision here favours the operator's file:
/// - an existing value is never overwritten, even if it is wrong (sanitising is
///   `parse`'s job, not the merge's)
/// - an existing table is never replaced wholesale, only descended into
/// - a value the operator deleted on purpose comes back, because `deny_unknown_fields`
///   means a removed key is indistinguishable from an old one. Documented.
///
/// `path` is only used to name the section in the added-key comment.
fn fill_missing(
    target: &mut toml_edit::Table,
    default: &toml_edit::Table,
    path: &str,
    added: &mut usize,
) {
    for (key, default_item) in default {
        let key_path: String = if path.is_empty() {
            key.to_string()
        } else {
            format!("{path}.{key}")
        };

        // The version is stamped by the caller, never merged from the default.
        if key == VERSION_KEY {
            continue;
        }

        // Messages are intentionally skipped. `Config::parse` already re-merges
        // the built-in strings in memory, and a file using the legacy flat
        // `[messages]` layout would break if `[messages.en]` were added next to
        // it: TOML cannot hold both a scalar and a sub-table under one key.
        if key == "messages" {
            continue;
        }

        match target.get_mut(key) {
            // Present: only descend when both sides are tables.
            Some(existing) => {
                if let (Some(existing_table), Some(default_table)) =
                    (existing.as_table_mut(), default_item.as_table())
                {
                    fill_missing(existing_table, default_table, &key_path, added);
                }
                // Anything else is a scalar the operator owns already.
            }
            // Absent: insert the default, carrying the marker comment if there
            // is one, so the new section still explains itself.
            None => {
                let mut item = default_item.clone();
                // Only a value carries decoration; a sub-table does not.
                if let (Some(value), Some(marker)) = (item.as_value_mut(), marker_for(default, key))
                {
                    value.decor_mut().set_prefix(marker);
                }
                target.insert(key, item);
                *added += 1;
            }
        }
    }
}

/// The `@pmcauto` marker block that precedes `key` in `table`, if any.
///
/// Used so a key inserted by a migration arrives with the operator-facing note
/// that says what it does, instead of appearing with no explanation.
fn marker_for(table: &toml_edit::Table, key: &str) -> Option<String> {
    let prefix = table.key(key)?.leaf_decor().prefix()?.as_str()?;
    if !prefix.contains(AUTO_MARKER) {
        return None;
    }
    Some(prefix.to_string())
}

/// Writes `bytes` to `path` by way of a sibling temporary file plus a rename.
///
/// The same rule the user database follows: a crash mid-write can leave a stray
/// `.tmp`, but it can never leave a half-written `config.toml` that then fails to
/// parse on the next start.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), LoadError> {
    // Append, do not replace the extension: `config.toml` would otherwise become
    // `config.tmp`, which a `config.toml.broken` backup could never overwrite.
    let tmp = path.with_file_name({
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        name
    });

    fs::write(&tmp, bytes).map_err(|e| LoadError::Io(format!("{}: {e}", tmp.display())))?;
    fs::rename(&tmp, path).map_err(|e| {
        // Best effort cleanup; the temp file is harmless if removal fails.
        let _ = fs::remove_file(&tmp);
        LoadError::Io(format!("{}: {e}", path.display()))
    })
}

/// Writes [`DEFAULT_CONFIG`] to `path`, atomically.
fn write_default(path: &Path) -> Result<(), LoadError> {
    write_atomic(path, DEFAULT_CONFIG.as_bytes())
}

#[derive(Debug, Clone)]
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
    fn rate_limit_scope_defaults_to_uuid_and_parses_both_spellings() {
        // Per-UUID is the only scope that is safe on an unknown topology.
        assert_eq!(
            Config::default().general.rate_limit_scope,
            RateLimitScope::Uuid
        );

        let uuid = Config::parse(
            r#"[general]
rate_limit_scope = "uuid""#,
        )
        .expect("uuid scope parses");
        assert_eq!(uuid.general.rate_limit_scope, RateLimitScope::Uuid);

        let ip = Config::parse(
            r#"[general]
rate_limit_scope = "ip""#,
        )
        .expect("ip scope parses");
        assert_eq!(ip.general.rate_limit_scope, RateLimitScope::Ip);

        // A typo must be a parse error, not a silent fallback to the weaker scope.
        assert!(
            Config::parse(
                r#"[general]
rate_limit_scope = "bogus""#
            )
            .is_err()
        );
    }

    #[test]
    fn missing_message_falls_back_to_key() {
        let config = Config::default();
        assert_eq!(config.message("does_not_exist", "en"), "does_not_exist");
    }

    #[test]
    fn premium_is_disabled_by_default() {
        // The whole feature must be inert on a default install.
        let config = Config::default();
        assert!(!config.premium.enabled);
        assert!(config.premium.trust_online_mode);
        assert!(!config.premium.trust_forwarded_profile);
        assert!(config.premium.require_claim);
        assert!(config.premium.block_linked_names);
        assert!(config.premium.link_requires_textures);
        assert!(!config.premium.log_decisions);
    }

    #[test]
    fn premium_without_any_anchor_is_forced_off() {
        // Enabling the feature with no trust anchor could never authenticate
        // anyone, so it is turned off instead of refusing every player.
        let config = Config::parse(
            r#"
            [premium]
            enabled = true
            trust_online_mode = false
            trust_forwarded_profile = false
            "#,
        )
        .expect("parse");

        assert!(!config.premium.enabled);
        assert!(!config.premium.any_anchor_enabled());
    }

    #[test]
    fn premium_stays_on_when_one_anchor_is_enabled() {
        let online = Config::parse(
            r#"
            [premium]
            enabled = true
            trust_online_mode = true
            trust_forwarded_profile = false
            "#,
        )
        .expect("parse");
        assert!(online.premium.enabled);

        // The proxy deployment an operator plans: config only, no recompile.
        let forwarded = Config::parse(
            r#"
            [premium]
            enabled = true
            trust_online_mode = false
            trust_forwarded_profile = true
            "#,
        )
        .expect("parse");
        assert!(forwarded.premium.enabled);
    }

    #[test]
    fn every_premium_message_exists_in_both_languages() {
        let config = Config::default();
        for key in [
            "premium_login_success",
            "premium_status_linked",
            "premium_status_not_linked",
            "premium_link_success",
            "premium_link_already",
            "premium_unlink_success",
            "premium_unlink_not_linked",
            "premium_unavailable",
            "premium_needs_profile",
            "premium_name_blocked",
            "premium_admin_requires_online",
        ] {
            for locale in ["en", "id"] {
                assert_ne!(
                    config.message(key, locale),
                    key,
                    "missing translation for {key} in {locale}"
                );
            }
        }
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

        assert_eq!(
            config.message("login_success", "id_id"),
            "Login berhasil. Selamat bermain!"
        );
        assert_eq!(
            config.message("login_success", "en_us"),
            "Login successful. Have fun!"
        );
        assert_eq!(
            config.message("login_success", "de_de"),
            "Login successful. Have fun!"
        );
    }

    #[test]
    fn every_builtin_language_defines_every_key() {
        let config = Config::default();
        let english = config
            .messages
            .get(DEFAULT_LANGUAGE)
            .expect("english built in");

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
        assert_eq!(
            config.message("reminder", "en"),
            "You are not logged in. {seconds} seconds left."
        );
    }

    // --- config versioning and migration ----------------------------------

    /// Writes `raw` to a fresh temp dir and returns the dir.
    fn write_config(name: &str, raw: &str) -> PathBuf {
        let dir = temp_dir(name);
        std::fs::write(dir.join("config.toml"), raw).expect("write config");
        dir
    }

    #[test]
    fn a_config_without_a_version_is_migrated_and_stamped() {
        // Exactly what 0.2.x wrote: no version key, no [premium] block.
        let raw = r#"# my settings
[general]
database_file = "users.json"
login_timeout_seconds = 60
"#;
        let dir = write_config("no-version", raw);

        let (_config, migration) = Config::load(&dir).expect("load");

        match migration {
            ConfigMigration::Written { from, to, added } => {
                assert_eq!(from, 0, "a missing version is version 0");
                assert_eq!(to, CONFIG_VERSION);
                assert!(added > 0, "the missing keys must be counted");
            }
            other => panic!("expected a write, got {other:?}"),
        }

        let migrated = std::fs::read_to_string(dir.join("config.toml")).expect("read");
        assert!(
            migrated.contains(&format!("config_version = {CONFIG_VERSION}")),
            "the file must be stamped: {migrated}"
        );
        assert!(
            migrated.contains("[premium]"),
            "the newer section must be merged in: {migrated}"
        );
        // The operator's own comment and values survive.
        assert!(migrated.contains("# my settings"));
        assert!(migrated.contains("login_timeout_seconds = 60"));
    }

    #[test]
    fn migration_keeps_every_value_the_operator_changed() {
        let raw = r#"config_version = 1
[general]
login_timeout_seconds = 999
min_password_length = 12
"#;
        let dir = write_config("keep-values", raw);

        let (config, _) = Config::load(&dir).expect("load");

        assert_eq!(
            config.general.login_timeout_seconds, 999,
            "the operator's value must win over the default"
        );
        assert_eq!(config.general.min_password_length, 12);

        let migrated = std::fs::read_to_string(dir.join("config.toml")).expect("read");
        assert!(migrated.contains("login_timeout_seconds = 999"));
        assert!(migrated.contains("min_password_length = 12"));
    }

    #[test]
    fn migration_fills_missing_keys_inside_an_existing_nested_table() {
        // The table exists, but one of its keys was deleted. The key must come
        // back inside that table, not as a stray root key.
        let raw = r#"config_version = 1
[general]
login_timeout_seconds = 60

[premium]
enabled = true
trust_online_mode = true
"#;
        let dir = write_config("nested", raw);

        let (config, migration) = Config::load(&dir).expect("load");

        assert!(migration.wrote(), "a missing nested key is a change");
        assert!(
            config.premium.enabled,
            "the operator's value survives the merge"
        );
        assert!(
            config.premium.require_claim,
            "a deleted key is restored from the default"
        );
        assert_eq!(
            config.general.login_timeout_seconds, 60,
            "an untouched value is unchanged"
        );

        // And it really landed inside [premium], not at the root.
        let migrated = std::fs::read_to_string(dir.join("config.toml")).expect("read");
        let premium_section = migrated
            .split("[premium]")
            .nth(1)
            .expect("premium section exists");
        assert!(
            premium_section.contains("require_claim"),
            "the key must be inside [premium]: {migrated}"
        );
    }

    #[test]
    fn legacy_flat_messages_table_is_not_split_into_two_tables() {
        // A pre-0.3 config has `[messages]` with plain strings. Injecting the
        // default's `[messages.en]` next to it would produce a document that no
        // longer parses, so the migration must descend into the existing table
        // (where `login_success` etc. already live) instead.
        let raw = r#"config_version = 1
[messages]
login_success = "Login berhasil versi lama"
"#;
        let dir = write_config("legacy-messages", raw);
        let path = dir.join("config.toml");

        let (config, _migration) = Config::load(&dir).expect("load");

        // Still readable, and the operator's wording is intact.
        assert_eq!(
            config.message("login_success", "en"),
            "Login berhasil versi lama"
        );

        // The result must round-trip as valid TOML.
        let migrated = std::fs::read_to_string(&path).expect("read");
        let reparsed: Config = toml::from_str(&migrated).expect("migrated file must stay valid");
        assert_eq!(
            reparsed.message("login_success", "en"),
            "Login berhasil versi lama"
        );
    }

    #[test]
    fn migration_preserves_comments() {
        let raw = r#"config_version = 1
# This comment explains a deliberate choice.
[general]
# Another one, above a value.
login_timeout_seconds = 30
"#;
        let dir = write_config("comments", raw);

        let (_config, migration) = Config::load(&dir).expect("load");
        assert!(migration.wrote());

        let migrated = std::fs::read_to_string(dir.join("config.toml")).expect("read");
        assert!(migrated.contains("# This comment explains a deliberate choice."));
        assert!(migrated.contains("# Another one, above a value."));
        assert!(migrated.contains("login_timeout_seconds = 30"));
    }

    #[test]
    fn the_shipped_default_is_already_current() {
        // Guards the release process: if someone adds a key to the default file
        // without bumping CONFIG_VERSION (or forgets the version key entirely),
        // the very first start would rewrite a file that is supposed to be final.
        let dir = temp_dir("shipped-default");
        std::fs::write(dir.join("config.toml"), DEFAULT_CONFIG).expect("write");

        let (_config, migration) = Config::load(&dir).expect("load");

        assert_eq!(
            migration,
            ConfigMigration::UpToDate,
            "the shipped default must need no migration of its own"
        );
    }

    #[test]
    fn migration_output_reparses_as_a_valid_config() {
        // The strongest single guarantee: whatever the merge produces must still
        // be loadable, or the next start would treat it as broken.
        let raw = r#"# operator notes
[general]
login_timeout_seconds = 45
[premium]
enabled = true
trust_online_mode = true
"#;
        let dir = write_config("reparse", raw);

        let (_config, migration) = Config::load(&dir).expect("load");
        assert!(migration.wrote());

        let migrated = std::fs::read_to_string(dir.join("config.toml")).expect("read");
        let reparsed: Config =
            toml::from_str(&migrated).expect("a migrated file must always parse");
        assert_eq!(reparsed.general.login_timeout_seconds, 45);
        assert!(reparsed.premium.enabled);
        assert!(
            reparsed.premium.require_claim,
            "the restored key is present"
        );

        // And loading once more changes nothing.
        let (_config, again) = Config::load(&dir).expect("reload");
        assert_eq!(again, ConfigMigration::UpToDate);
    }

    #[test]
    fn an_up_to_date_config_is_not_rewritten() {
        // Load the shipped default once: it is complete and current.
        let dir = temp_dir("up-to-date");
        Config::load(&dir).expect("first load");
        let path = dir.join("config.toml");
        let before = std::fs::read_to_string(&path).expect("read");

        let (_config, migration) = Config::load(&dir).expect("second load");

        assert_eq!(
            migration,
            ConfigMigration::UpToDate,
            "a complete config must not be rewritten"
        );
        assert!(
            !migration.wrote(),
            "nothing may touch the disk on a normal start"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            before,
            "the file bytes must be identical"
        );
    }

    #[test]
    fn migration_is_idempotent_across_repeated_loads() {
        // Start from an old file, then load it three more times.
        let dir = write_config("idempotent", "[general]\nlogin_timeout_seconds = 42\n");

        Config::load(&dir).expect("first load migrates");
        let after_first = std::fs::read_to_string(dir.join("config.toml")).expect("read");

        for _ in 0..3 {
            let (_config, migration) = Config::load(&dir).expect("reload");
            assert_eq!(
                migration,
                ConfigMigration::UpToDate,
                "only the first load may write"
            );
        }

        assert_eq!(
            std::fs::read_to_string(dir.join("config.toml")).expect("read"),
            after_first,
            "repeated loads must not keep changing the file"
        );
    }

    #[test]
    fn an_invalid_file_is_replaced_and_never_merged() {
        let dir = write_config("invalid", "this is not toml [[[");
        let path = dir.join("config.toml");

        let (_config, migration) = Config::load(&dir).expect("a usable config is still returned");

        assert!(
            matches!(migration, ConfigMigration::ReplacedBroken { .. }),
            "the caller must be told: {migration:?}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("config.toml.broken")).expect("backup"),
            "this is not toml [[[",
            "the broken file is preserved"
        );
        assert!(
            std::fs::read_to_string(&path)
                .expect("rewritten")
                .contains("config_version"),
            "the replacement is a current default"
        );
    }

    #[test]
    fn a_future_version_is_never_downgraded() {
        // A file written by a newer plugin may still be missing keys this build
        // knows about; filling them is fine. Overwriting its version with an older
        // one is not, because that would trigger a pointless rewrite next start.
        let future = CONFIG_VERSION + 1;
        let dir = write_config(
            "future",
            &format!("config_version = {future}\n[general]\nlogin_timeout_seconds = 60\n"),
        );

        let (_config, _migration) = Config::load(&dir).expect("load");

        let migrated = std::fs::read_to_string(dir.join("config.toml")).expect("read");
        assert!(
            migrated.contains(&format!("config_version = {future}")),
            "the newer version must be preserved: {migrated}"
        );
    }

    #[test]
    fn a_complete_future_version_file_is_left_untouched() {
        let future = CONFIG_VERSION + 1;
        let mut raw = DEFAULT_CONFIG.replace(
            &format!("config_version = {CONFIG_VERSION}"),
            &format!("config_version = {future}"),
        );
        assert!(
            raw.contains(&future.to_string()),
            "the test setup must work"
        );

        let dir = write_config("future-complete", &raw);
        let before = std::fs::read_to_string(dir.join("config.toml")).expect("read");
        raw.clear();

        let (_config, migration) = Config::load(&dir).expect("load");

        assert_eq!(
            migration,
            ConfigMigration::UpToDate,
            "a complete newer file must not be rewritten"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("config.toml")).expect("read"),
            before
        );
    }

    #[test]
    fn load_regenerates_a_missing_config() {
        let dir = temp_dir("missing");
        let path = dir.join("config.toml");
        assert!(!path.exists());

        let (config, migration) = Config::load(&dir).expect("load writes and parses the default");

        assert!(path.exists(), "a deleted config must be recreated");
        assert_eq!(config.general.database_file, "users.json");
        assert!(
            migration.wrote(),
            "a fresh file is reported as written, not as up to date"
        );

        // Deleting it again after the directory already exists must also work.
        std::fs::remove_file(&path).expect("remove");
        Config::load(&dir).expect("second load");
        assert!(
            path.exists(),
            "regenerated on every start, not just the first"
        );
    }

    #[test]
    fn load_replaces_a_broken_config_and_keeps_a_copy() {
        let dir = temp_dir("broken");
        let path = dir.join("config.toml");
        std::fs::write(&path, "this is not toml [[[").expect("write");

        let (_config, migration) = Config::load(&dir).expect("a broken file still yields a config");

        assert!(
            matches!(migration, ConfigMigration::ReplacedBroken { .. }),
            "the operator must be told the file was broken: {migration:?}"
        );
        let recovered = std::fs::read_to_string(&path).expect("config rewritten");
        assert!(
            recovered.contains("[messages.en]"),
            "the file is replaced with a working default"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("config.toml.broken")).expect("backup kept"),
            "this is not toml [[[",
            "the broken file is preserved, never silently destroyed"
        );
    }

    /// Unique per test: the suite runs in parallel and must not share a directory.
    fn temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("pmcauth-config-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path
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
