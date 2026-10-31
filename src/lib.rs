//! PMCAuth — AuthMe-style login/registration for Pumpkin MC.
//!
//! Players must `/register` or `/login` before they can move, chat, use commands,
//! interact, or touch blocks. Accounts are stored in a JSON file inside the
//! plugin's private data folder; passwords are Argon2id hashes.
//!
//! Why no SQLite: `rusqlite` needs the WASI SDK to cross-compile C, and the
//! bundled WASI VFS has no file locking, so WAL is unavailable. For a table of
//! one row per player a JSON file is smaller, dependency-free and fast enough.
//! The `UserStore` trait keeps the door open for a SQLite backend later.

pub mod auth;
pub mod commands;
pub mod config;
pub mod events;
pub mod security;
pub mod state;
pub mod storage;

use std::path::Path;
use std::sync::Arc;

use pumpkin_plugin_api::permissions;
use pumpkin_plugin_api::scheduler::SchedulerExt;
use pumpkin_plugin_api::text::{NamedColor, TextComponent};
use pumpkin_plugin_api::{Context, Plugin, PluginMetadata, Result, Server};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::state::{AuthState, now_unix};
use crate::storage::{FileStore, UserStore};

/// How often the timeout/reminder task runs, in ticks (20 ticks = 1 second).
const TICK_PERIOD: u64 = 20;

/// Plugin name reported to the host. It is also the required permission
/// namespace, so permission nodes must be prefixed with `"PMCAuth:"`.
pub const PLUGIN_NAME: &str = "PMCAuth";

pub struct PmcAuth {
    state: std::sync::OnceLock<Arc<AuthState>>,
}

impl PmcAuth {
    fn state(&self) -> Option<Arc<AuthState>> {
        self.state.get().cloned()
    }
}

impl Plugin for PmcAuth {
    fn new() -> Self {
        Self {
            state: std::sync::OnceLock::new(),
        }
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: PLUGIN_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            authors: vec!["PMCAuth".to_string()],
            description: "AuthMe-style login and registration for Pumpkin".to_string(),
            dependencies: Vec::new(),
            // Without these the data folder is not preopened into the WASI sandbox.
            permissions: vec![
                permissions::FS_READ_DATA.to_string(),
                permissions::FS_WRITE_DATA.to_string(),
            ],
        }
    }

    fn on_load(&self, context: Context) -> Result<()> {
        let data_dir = context.get_data_folder();
        // One-shot breadcrumb: the sandbox path is only known at runtime and this
        // is the first thing to check when the database "disappears".
        info!("PMCAuth data folder: {data_dir}");

        let dir = Path::new(&data_dir);
        if let Err(e) = std::fs::create_dir_all(dir) {
            return Err(format!("cannot create data folder {data_dir}: {e}"));
        }

        let config = match Config::load(dir) {
            Ok(config) => config,
            Err(e) => {
                // Booting with defaults beats refusing to start, but the operator
                // must be able to see why their settings are being ignored.
                error!("PMCAuth: {e}; falling back to defaults");
                Config::default()
            }
        };

        let db_path = config.database_path(dir);
        let store = FileStore::open(&db_path)
            .map_err(|e| format!("cannot open user database {}: {e}", db_path.display()))?;

        let accounts = store.len();
        let state = Arc::new(AuthState::new(config, store));

        commands::register_permissions(&context)?;
        commands::register_commands(&context, state.clone())?;
        events::register(&context, state.clone())?;

        start_maintenance_task(&context, state.clone());
        self.state
            .set(state)
            .map_err(|_| "PMCAuth was already initialised".to_string())?;

        info!(
            "PMCAuth loaded: {accounts} account(s) in {}",
            db_path.display()
        );
        Ok(())
    }

    fn on_unload(&self, _context: Context) -> Result<()> {
        if let Some(state) = self.state() {
            if let Err(e) = state.flush_store() {
                // Do not fail unload over a flush error; report it and continue.
                error!("PMCAuth: failed to flush user database on unload: {e}");
            }
            info!("PMCAuth unloaded.");
        }
        Ok(())
    }
}

/// Repeating task: kick players whose login timeout expired, remind the rest, and
/// prune stale IP sessions / lockouts.
fn start_maintenance_task(context: &Context, state: Arc<AuthState>) {
    context.schedule_repeating_task(0, TICK_PERIOD, move |server: Server| {
        tick(&state, &server);
    });
}

fn tick(state: &AuthState, server: &Server) {
    let config = state.config();
    let now = now_unix();

    // --- timeouts ---
    for uuid in state.expired_sessions(now) {
        let Some(player) = find_player_by_uuid(server, &uuid) else {
            // Player already gone; nothing to kick.
            state.remove_session(&uuid);
            continue;
        };

        if config.general.kick_on_timeout {
            state.remove_session(&uuid);
            let locale = player.get_locale();
            kick(&player, config.message("kicked_timeout", &locale));
        } else {
            // Keep them frozen and restart the clock.
            state.remove_session(&uuid);
            state.create_session(
                &uuid,
                &player.get_ip(),
                now,
                config.general.login_timeout_seconds,
                config.general.reminder_interval_seconds,
            );
            player.set_movement_locked(true);
            crate::events::send_prompt(state, &player);
        }
    }

    // --- reminders ---
    if config.general.reminder_interval_seconds > 0 {
        for (uuid, _) in state.due_reminders(now) {
            let Some(player) = find_player_by_uuid(server, &uuid) else {
                state.remove_session(&uuid);
                continue;
            };

            let session = state.bump_reminder(&uuid, config.general.reminder_interval_seconds);
            let remaining = session
                .as_ref()
                .map(|s| s.deadline.saturating_sub(now))
                .unwrap_or(0);

            let locale = player.get_locale();
            let text = config
                .message("reminder", &locale)
                .replace("{seconds}", &remaining.to_string());
            let component = TextComponent::text(&text).color_named(NamedColor::Yellow);
            player.send_system_message(component, true);
        }
    }

    // --- housekeeping ---
    state.prune_ip_sessions(now);
    state.prune_lockouts(now);
}

/// Looks a player up by UUID string.
///
/// Only used by the maintenance task, where the player may already be gone.
fn find_player_by_uuid(server: &Server, uuid: &str) -> Option<pumpkin_plugin_api::Player> {
    server
        .get_all_players()
        .into_iter()
        .find(|player| player.get_id().to_string() == uuid)
}

/// Disconnects a player, handling both editions.
///
/// `Player` has no `kick` of its own: it lives on the Java and Bedrock handles.
fn kick(player: &pumpkin_plugin_api::Player, message: &str) -> bool {
    if let Some(java) = player.as_java() {
        let options = pumpkin_plugin_api::player::JavaKickOptions::new(TextComponent::text(message));
        java.kick(options);
        return true;
    }
    if let Some(bedrock) = player.as_bedrock() {
        // Bedrock takes a plain string plus a protocol reason code.
        let options = pumpkin_plugin_api::player::BedrockKickOptions::new(
            pumpkin_plugin_api::player::BedrockDisconnectReason::Kicked,
            message,
        );
        bedrock.kick(&options);
        return true;
    }

    // Unknown edition: free the slot so the task stops retrying.
    warn!("PMCAuth: cannot kick player {} (unknown edition)", player.get_name());
    false
}

pumpkin_plugin_api::register_plugin!(PmcAuth);
