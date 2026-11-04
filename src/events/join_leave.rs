//! Join and leave handling.
//!
//! On join the player is frozen immediately, given a login session and told what
//! to do. If an IP session is valid they are authenticated straight away. On leave
//! the in-memory session is dropped so a reconnect starts clean.

use std::sync::Arc;

use pumpkin_plugin_api::events::{EventData, EventHandler, PlayerJoinEvent, PlayerLeaveEvent};
use pumpkin_plugin_api::text::TextComponent;
use pumpkin_plugin_api::{Player, Server};
use tracing::info;

use crate::auth::{PremiumDecision, autologin_decision};
use crate::events::premium_anchor;
use crate::state::{AuthState, now_unix, parse_ip};

pub struct JoinHandler(pub Arc<AuthState>);

impl EventHandler<PlayerJoinEvent> for JoinHandler {
    fn handle(
        &self,
        server: Server,
        event: EventData<PlayerJoinEvent>,
    ) -> EventData<PlayerJoinEvent> {
        authenticate_on_join(&self.0, &server, &event.player);
        event
    }
}

fn authenticate_on_join(state: &AuthState, server: &Server, player: &Player) {
    let config = state.config();
    let uuid = player.get_id().to_string();
    let name = player.get_name();
    let ip = player.get_ip();
    let now = now_unix();

    // 1. Same IP within the configured window: skip the password entirely.
    // `get_ip()` yields `ip:port`, so this must compare the bare address.
    if let Some(addr) = parse_ip(&ip)
        && config.general.session_minutes > 0
        && state.ip_session_valid(addr, now)
    {
        state.remove_session(&uuid);
        state.set_authenticated(&uuid);
        player.set_movement_locked(false);
        let locale = player.get_locale();
        let message = config.message("login_success", &locale);
        player.send_system_message(TextComponent::text(message), false);
        return;
    }

    // 2. Premium: only when every condition holds. Anything else falls through to
    //    the password flow below, exactly as before this feature existed.
    if config.premium.enabled {
        let anchor = premium_anchor(state, server, player);
        let record = state.account_for(&uuid, &name);
        let decision = autologin_decision(&config.premium, anchor, &uuid, record.as_ref());

        if config.premium.log_decisions {
            info!(
                "PMCAuth: premium join for {} (uuid {}): {decision:?}, anchor {anchor:?}",
                name, uuid
            );
        }

        if let PremiumDecision::AutoLogin { .. } = decision {
            state.remove_session(&uuid);
            state.set_authenticated(&uuid);
            player.set_movement_locked(false);
            let locale = player.get_locale();
            let message = config.message("premium_login_success", &locale);
            player.send_system_message(TextComponent::text(message), false);
            return;
        }
    }

    // 3. Otherwise: freeze and start the clock.
    state.clear_authenticated(&uuid);
    state.create_session(
        &uuid,
        &ip,
        now,
        config.general.login_timeout_seconds,
        config.general.reminder_interval_seconds,
    );

    player.set_movement_locked(true);
    // Seed the anchor now, while the server still owns the spawn position. It
    // must never come from a movement packet: the client has already been
    // drifting during its loading screen by the time the first one arrives.
    crate::events::bedrock_freeze::set_anchor(state, player);
    crate::events::send_prompt(state, player);
}

pub struct LeaveHandler(pub Arc<AuthState>);

impl EventHandler<PlayerLeaveEvent> for LeaveHandler {
    fn handle(
        &self,
        _server: Server,
        event: EventData<PlayerLeaveEvent>,
    ) -> EventData<PlayerLeaveEvent> {
        let uuid = event.player.get_id().to_string();

        // A player who left while still unauthenticated is returned to its
        // anchor first, so the position that gets saved is the one it was held
        // at rather than wherever the client had wandered. `remove_session`
        // drops the anchor itself, so this has to happen before it.
        crate::events::bedrock_freeze::snap_to_anchor(&self.0, &event.player);

        // A player who left while still unauthenticated must not keep a session
        // entry, otherwise the timeout task would try to kick a ghost.
        self.0.remove_session(&uuid);
        self.0.clear_authenticated(&uuid);

        // Persist anything still buffered before the player is gone.
        let _ = self.0.flush_store();
        event
    }
}
