//! Event handlers.
//!
//! Two groups: lifecycle (join/leave) and the "not logged in" guards that cancel
//! whatever the frozen player tries to do.

pub mod guard;
pub mod join_leave;

use std::sync::Arc;

use pumpkin_plugin_api::Player;
use pumpkin_plugin_api::events::EventPriority;
use pumpkin_plugin_api::{Context, text::TextComponent};

use crate::state::AuthState;

/// Registers every handler. All are blocking: we must be able to cancel.
pub fn register(context: &Context, state: Arc<AuthState>) -> pumpkin_plugin_api::Result<()> {
    context.register_event_handler(
        join_leave::JoinHandler(state.clone()),
        EventPriority::Highest,
        true,
    )?;
    context.register_event_handler(
        join_leave::LeaveHandler(state.clone()),
        EventPriority::Highest,
        true,
    )?;

    guard::register_all(context, state)?;
    Ok(())
}

/// Called after a successful register/login/forcelogin.
///
/// Clears the freeze, drops the pending session and tells the player.
pub fn on_authenticated(state: &AuthState, player: &Player) {
    let config = state.config();
    let message = config.message("login_success");
    on_authenticated_silently(state, player);
    player.send_system_message(TextComponent::text(message), false);
}

/// The state part of [`on_authenticated`], without the success message.
///
/// Used by `/authadmin forcelogin`, where the operator already gets a reply and
/// the target should not also see "login successful".
pub fn on_authenticated_silently(state: &AuthState, player: &Player) {
    let uuid = player.get_id().to_string();

    state.remove_session(&uuid);
    state.set_authenticated(&uuid);
    player.set_movement_locked(false);
}

/// Called after /logout: freeze the player again and arm a fresh login session.
pub fn on_deauthenticated(state: &AuthState, player: &Player) {
    let config = state.config();
    let uuid = player.get_id().to_string();
    let ip = player.get_ip();

    state.clear_authenticated(&uuid);
    state.revoke_ip_session(&ip);
    state.create_session(
        &uuid,
        &ip,
        crate::state::now_unix(),
        config.general.login_timeout_seconds,
        config.general.reminder_interval_seconds,
    );

    player.set_movement_locked(true);
    send_prompt(state, player);
}

/// Sends the single prompt an unauthenticated player needs.
///
/// A registered account only needs `/login`; anyone else needs `/register`.
pub fn send_prompt(state: &AuthState, player: &Player) {
    let config = state.config();
    let key = if state.is_registered(&player.get_id().to_string(), &player.get_name()) {
        "login_prompt"
    } else {
        "register_prompt"
    };
    player.send_system_message(TextComponent::text(config.message(key)), false);
}
