//! Event handlers.
//!
//! Two groups: lifecycle (join/leave) and the "not logged in" guards that cancel
//! whatever the frozen player tries to do.

pub mod bedrock_freeze;
pub mod guard;
pub mod join_leave;

use std::sync::Arc;

use pumpkin_plugin_api::Player;
use pumpkin_plugin_api::events::EventPriority;
use pumpkin_plugin_api::{Context, Server, text::TextComponent};

use crate::auth::PremiumAnchor;
use crate::state::{AuthState, parse_ip};

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

    // `set_movement_locked` is ignored on the Bedrock path by the host, and the
    // Bedrock movement packet is never decoded, so the hold is anchor + teleport
    // instead of packet interception. The tick calls `bedrock_freeze::hold`;
    // this handler only keeps the anchor valid across a respawn.
    context.register_event_handler(
        bedrock_freeze::RespawnAnchorGuard(state.clone()),
        EventPriority::Highest,
        true,
    )?;

    guard::register_all(context, state)?;
    Ok(())
}

/// Called after a successful register/login/forcelogin.
///
/// Clears the freeze and drops the pending session. It deliberately sends no
/// message: every caller has already replied with its own success text, and
/// sending here as well made the player see "Login berhasil" twice.
pub fn on_authenticated(state: &AuthState, player: &Player) {
    let uuid = player.get_id().to_string();

    // Return the player to where it was held before releasing it. Any drift
    // accumulated during the login window is discarded here rather than carried
    // into play. This must run before `remove_session`, which drops the anchor.
    bedrock_freeze::snap_to_anchor(state, player);

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
    if let Some(addr) = parse_ip(&ip) {
        state.revoke_ip_session(addr);
    }
    state.create_session(
        &uuid,
        &ip,
        crate::state::now_unix(),
        config.general.login_timeout_seconds,
        config.general.reminder_interval_seconds,
    );

    player.set_movement_locked(true);
    // `/logout` re-freezes, so it needs its own anchor: the join-time one was
    // dropped by `on_authenticated` when the player logged in.
    bedrock_freeze::set_anchor(state, player);
    send_prompt(state, player);
}

/// Works out which proof, if any, says this connection is Mojang-authenticated.
///
/// Order matters only for the log message: online mode is the stronger claim, and
/// a forwarded profile is never trusted on its own when it has no textures.
///
/// `server.is_online_mode()` is the only network-state getter the v0.1 WIT
/// exposes; there is no way to ask whether proxy forwarding is actually on.
pub fn premium_anchor(state: &AuthState, server: &Server, player: &Player) -> PremiumAnchor {
    let premium = &state.config().premium;
    if !premium.enabled {
        return PremiumAnchor::None;
    }

    if premium.trust_online_mode && server.is_online_mode() {
        return PremiumAnchor::OnlineMode;
    }

    if premium.trust_forwarded_profile {
        // A bare offline server never fills the property list, so this can only be
        // true when something upstream supplied a real profile.
        if player.get_skin().is_some() {
            return PremiumAnchor::ForwardedProfile;
        }
    }

    PremiumAnchor::None
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
    let locale = player.get_locale();
    player.send_system_message(TextComponent::text(config.message(key, &locale)), false);
}
