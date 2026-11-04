//! Anchor + teleport hold for players who have not authenticated yet.
//!
//! # Why not packet interception
//!
//! The previous version cancelled the Bedrock movement packet
//! (`SPlayerAuthInput`, id 144). That could not work: the host builds
//! `PacketReceivedEvent` with
//! `deserialize_bedrock_serverbound_packet(...).map_or(Unknown, Bedrock)`, and
//! the generated deserializer in `pumpkin-wasm-host-v0_1/src/generated_packets.rs`
//! has **no arm for id 144**. Every movement packet therefore arrives as
//! `ServerboundPacket::Unknown`, so matching the decoded variant never fired.
//! Even matching the numeric id only hid the real problem: the Bedrock client
//! predicts its own movement, so refusing a packet does not stop it from moving
//! on the player's screen.
//!
//! # What this does instead
//!
//! 1. **Seed the anchor at join**, while the server still owns the spawn
//!    position. The client can drift during its loading screen, so the anchor
//!    must never be taken from a movement packet.
//! 2. **Hold**: the maintenance tick returns a drifted player to the anchor with
//!    `Player::teleport`, which on the Bedrock path sends `MovePlayer` with
//!    `MODE_TELEPORT` (`entity/player.rs`, `request_teleport`). That is a
//!    server-initiated correction the client obeys, and it needs no packet
//!    inspection at all.
//! 3. **Snap on success**: the same teleport runs once authentication lands, so
//!    any drift during the login window is discarded instead of carrying over
//!    into play.
//! 4. **Reset on disconnect**: the player is returned to the anchor before the
//!    leave handler flushes, so the saved position is the anchor rather than
//!    wherever the client had wandered.
//!
//! The anchor is per-UUID and dropped with the login session, so nothing
//! outlives the window it was created for.

use std::sync::Arc;

use pumpkin_plugin_api::Player;
use pumpkin_plugin_api::events::{EventData, EventHandler, PlayerRespawnEvent};

use crate::state::AuthState;

/// How far a player may drift from the anchor before being pulled back.
///
/// Squared distance in metres squared. This is deliberately below one block so
/// a real step is always caught; jitter well under a block is ignored.
const DRIFT_SQUARED: f64 = 0.25;

/// Whether `actual` is far enough from `anchor` to need a correction.
///
/// Split out from [`hold`] so the threshold is testable without a live player.
///
/// Non-finite coordinates count as drift and are checked explicitly: every
/// comparison against `NaN` is false, so a plain `distance > DRIFT_SQUARED`
/// would treat a broken position as "in place" and leave the player wherever
/// the client put it. Reasserting the anchor is the safe answer.
fn drifted(anchor: (f64, f64, f64), actual: (f64, f64, f64)) -> bool {
    let (ax, ay, az) = anchor;
    let (x, y, z) = actual;
    if !ax.is_finite() || !ay.is_finite() || !az.is_finite() {
        // The anchor itself is unusable; nothing to correct towards.
        return false;
    }
    if !x.is_finite() || !y.is_finite() || !z.is_finite() {
        return true;
    }

    let dx = x - ax;
    let dy = y - ay;
    let dz = z - az;
    dx * dx + dy * dy + dz * dz > DRIFT_SQUARED
}

/// Returns a drifted player to the anchor, if one is recorded.
///
/// Returns `true` when a teleport was actually sent, so callers that care can
/// distinguish "already in place" from "corrected". No anchor means the player
/// is not being held (authenticated, Java, or no session), so this is a no-op.
pub fn hold(state: &AuthState, player: &Player) -> bool {
    let uuid = player.get_id().to_string();
    let Some(anchor) = state.anchor(&uuid) else {
        return false;
    };

    if !drifted(anchor, player.get_position()) {
        return false;
    }

    // `yaw` and `pitch` stay `None` so the view is not snapped around while the
    // player is reading the login prompt.
    player.teleport(anchor, None, None, player.get_world());
    true
}

/// Sends the player to the anchor unconditionally, ignoring the drift threshold.
///
/// Used on the two transitions where the exact position matters more than
/// avoiding a redundant packet: a completed login and a disconnect.
pub fn snap_to_anchor(state: &AuthState, player: &Player) {
    let uuid = player.get_id().to_string();
    let Some(anchor) = state.anchor(&uuid) else {
        return;
    };
    player.teleport(anchor, None, None, player.get_world());
}

/// Records the position to hold a player at. Called once, at join.
pub fn set_anchor(state: &AuthState, player: &Player) {
    state.set_anchor(&player.get_id().to_string(), player.get_position());
}

/// Drops the anchor for a player who is no longer being held.
pub fn clear_anchor(state: &AuthState, player: &Player) {
    state.clear_anchor(&player.get_id().to_string());
}

/// Re-anchors after a respawn.
///
/// A respawn moves the player, and the old anchor would immediately drag them
/// back to the pre-death position. Respawn is not cancellable, so the correct
/// response is to accept the new position as the place to hold.
pub struct RespawnAnchorGuard(pub Arc<AuthState>);

impl EventHandler<PlayerRespawnEvent> for RespawnAnchorGuard {
    fn handle(
        &self,
        _server: pumpkin_plugin_api::Server,
        event: EventData<PlayerRespawnEvent>,
    ) -> EventData<PlayerRespawnEvent> {
        let uuid = event.player.get_id().to_string();
        if self.0.is_authenticated(&uuid) {
            return event;
        }
        if self.0.anchor(&uuid).is_some() {
            self.0.set_anchor(&uuid, event.player.get_position());
        }
        event
    }
}

#[cfg(test)]
mod tests {
    use super::drifted;

    const ORIGIN: (f64, f64, f64) = (0.0, 64.0, 0.0);

    #[test]
    fn standing_still_is_not_drift() {
        assert!(!drifted(ORIGIN, ORIGIN));
    }

    #[test]
    fn a_one_block_step_is_drift() {
        // Walking one block in any direction must be corrected.
        assert!(drifted(ORIGIN, (1.0, 64.0, 0.0)));
        assert!(drifted(ORIGIN, (0.0, 65.0, 0.0)));
        assert!(drifted(ORIGIN, (0.0, 64.0, 1.0)));
        assert!(drifted(ORIGIN, (-1.0, 64.0, 0.0)));
    }

    #[test]
    fn sub_metre_jitter_is_not_drift() {
        // Otherwise an idle player would be teleported on every tick. The
        // threshold is 0.5 blocks, so this stays under it on every axis.
        assert!(!drifted(ORIGIN, (0.1, 64.0, 0.1)));
        assert!(!drifted(ORIGIN, (0.4, 64.0, 0.0)));
        assert!(!drifted(ORIGIN, (0.0, 64.4, 0.0)));
    }

    #[test]
    fn just_past_half_a_block_is_drift() {
        // Boundary: 0.25 squared is the cutoff, 0.6 squared exceeds it.
        assert!(drifted(ORIGIN, (0.6, 64.0, 0.0)));
    }

    #[test]
    fn a_large_jump_is_drift() {
        assert!(drifted(ORIGIN, (100.0, 200.0, -100.0)));
    }

    #[test]
    fn non_finite_positions_are_drift() {
        // An unusable position must reassert the anchor rather than be accepted.
        assert!(drifted(ORIGIN, (f64::NAN, 64.0, 0.0)));
        assert!(drifted(ORIGIN, (f64::INFINITY, 64.0, 0.0)));
    }
}
