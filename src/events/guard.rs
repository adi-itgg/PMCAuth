//! Guards that cancel everything a not-yet-authenticated player tries to do.
//!
//! Defence in depth: `set_movement_locked(true)` already freezes movement, but a
//! frozen player can still chat, click blocks and open containers. Each handler
//! bails out early for authenticated players, so the cost is one hashmap lookup.

use std::sync::Arc;

use pumpkin_plugin_api::events::{
    BlockBreakEvent, BlockPlaceEvent, EventHandler, EventPriority, InventoryClickEvent,
    InventoryOpenEvent, PlayerChatEvent, PlayerCommandPreprocessEvent, PlayerDropItemEvent,
    PlayerInteractAtEntityEvent, PlayerInteractEntityEvent, PlayerInteractEvent,
    PlayerItemConsumeEvent, PlayerMoveEvent,
};
use pumpkin_plugin_api::text::TextComponent;
use pumpkin_plugin_api::{Context, Player};

use crate::commands::is_public_command;
use crate::state::AuthState;

/// Sends the configured "log in first" message.
fn deny(state: &AuthState, player: &Player) {
    let config = state.config();
    player.send_system_message(
        TextComponent::text(config.message("deny_generic")),
        true,
    );
}

pub fn register_all(context: &Context, state: Arc<AuthState>) -> pumpkin_plugin_api::Result<()> {
    macro_rules! register {
        ($handler:expr) => {
            context.register_event_handler($handler, EventPriority::Highest, true)?;
        };
    }

    register!(MoveHandler(state.clone()));
    register!(ChatHandler(state.clone()));
    register!(CommandHandler(state.clone()));
    register!(InteractBlockHandler(state.clone()));
    register!(InteractEntityHandler(state.clone()));
    register!(InteractAtEntityHandler(state.clone()));
    register!(BlockBreakHandler(state.clone()));
    register!(BlockPlaceHandler(state.clone()));
    register!(DropItemHandler(state.clone()));
    register!(ConsumeItemHandler(state.clone()));
    register!(InventoryClickHandler(state.clone()));
    register!(InventoryOpenHandler(state));

    Ok(())
}

// --- individual handlers --------------------------------------------------

struct MoveHandler(Arc<AuthState>);

impl EventHandler<PlayerMoveEvent> for MoveHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<PlayerMoveEvent>,
    ) -> pumpkin_plugin_api::events::EventData<PlayerMoveEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
        }
        event
    }
}

struct ChatHandler(Arc<AuthState>);

impl EventHandler<PlayerChatEvent> for ChatHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<PlayerChatEvent>,
    ) -> pumpkin_plugin_api::events::EventData<PlayerChatEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
            deny(&self.0, &event.player);
        }
        event
    }
}

struct CommandHandler(Arc<AuthState>);

impl EventHandler<PlayerCommandPreprocessEvent> for CommandHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<PlayerCommandPreprocessEvent>,
    ) -> pumpkin_plugin_api::events::EventData<PlayerCommandPreprocessEvent> {
        let authenticated = self.0.is_authenticated(&event.player.get_id().to_string());
        let public = is_public_command(&event.command);

        let should_cancel = match (authenticated, public) {
            // Not logged in: only /login and /register may pass.
            (false, true) => false,
            (false, false) => {
                deny(&self.0, &event.player);
                true
            }
            // Logged in: re-running /login or /register is pointless.
            (true, true) => true,
            (true, false) => false,
        };

        event.cancelled = should_cancel;
        event
    }
}

struct InteractBlockHandler(Arc<AuthState>);

impl EventHandler<PlayerInteractEvent> for InteractBlockHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<PlayerInteractEvent>,
    ) -> pumpkin_plugin_api::events::EventData<PlayerInteractEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
        }
        event
    }
}

struct InteractEntityHandler(Arc<AuthState>);

impl EventHandler<PlayerInteractEntityEvent> for InteractEntityHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<PlayerInteractEntityEvent>,
    ) -> pumpkin_plugin_api::events::EventData<PlayerInteractEntityEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
        }
        event
    }
}

struct InteractAtEntityHandler(Arc<AuthState>);

impl EventHandler<PlayerInteractAtEntityEvent> for InteractAtEntityHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<PlayerInteractAtEntityEvent>,
    ) -> pumpkin_plugin_api::events::EventData<PlayerInteractAtEntityEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
        }
        event
    }
}

struct BlockBreakHandler(Arc<AuthState>);

impl EventHandler<BlockBreakEvent> for BlockBreakHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<BlockBreakEvent>,
    ) -> pumpkin_plugin_api::events::EventData<BlockBreakEvent> {
        if let Some(player) = &event.player
            && !self.0.is_authenticated(&player.get_id().to_string())
        {
            event.cancelled = true;
        }
        event
    }
}

struct BlockPlaceHandler(Arc<AuthState>);

impl EventHandler<BlockPlaceEvent> for BlockPlaceHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<BlockPlaceEvent>,
    ) -> pumpkin_plugin_api::events::EventData<BlockPlaceEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
        }
        event
    }
}

struct DropItemHandler(Arc<AuthState>);

impl EventHandler<PlayerDropItemEvent> for DropItemHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<PlayerDropItemEvent>,
    ) -> pumpkin_plugin_api::events::EventData<PlayerDropItemEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
        }
        event
    }
}

struct ConsumeItemHandler(Arc<AuthState>);

impl EventHandler<PlayerItemConsumeEvent> for ConsumeItemHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<PlayerItemConsumeEvent>,
    ) -> pumpkin_plugin_api::events::EventData<PlayerItemConsumeEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
        }
        event
    }
}

struct InventoryClickHandler(Arc<AuthState>);

impl EventHandler<InventoryClickEvent> for InventoryClickHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<InventoryClickEvent>,
    ) -> pumpkin_plugin_api::events::EventData<InventoryClickEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
        }
        event
    }
}

struct InventoryOpenHandler(Arc<AuthState>);

impl EventHandler<InventoryOpenEvent> for InventoryOpenHandler {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        mut event: pumpkin_plugin_api::events::EventData<InventoryOpenEvent>,
    ) -> pumpkin_plugin_api::events::EventData<InventoryOpenEvent> {
        if !self.0.is_authenticated(&event.player.get_id().to_string()) {
            event.cancelled = true;
        }
        event
    }
}
