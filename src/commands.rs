//! Command registration and handlers.
//!
//! Thin translation layer: pull `sender`/`args`, call into [`crate::auth`], render
//! the reply, send it. No auth rules live here.

use std::sync::Arc;

use pumpkin_plugin_api::command::{
    Arg, Command, CommandError, CommandNode, CommandSender, ConsumedArgs,
};
use pumpkin_plugin_api::permission::{Permission, PermissionDefault};
use pumpkin_plugin_api::{Context, Server, text::TextComponent};

use crate::events::premium_anchor;
use crate::state::AuthState;
use crate::storage::lowercase;

// The host rejects a permission whose node does not start with
// `"{metadata.name}:"`, compared case-sensitively, so the prefix must be
// "PMCAuth:" exactly -- not the lowercase plugin id.
pub const PERM_REGISTER: &str = "PMCAuth:command.register";
pub const PERM_LOGIN: &str = "PMCAuth:command.login";
pub const PERM_LOGOUT: &str = "PMCAuth:command.logout";
pub const PERM_CHANGEPASSWORD: &str = "PMCAuth:command.changepassword";
pub const PERM_PREMIUM: &str = "PMCAuth:command.premium";
pub const PERM_ADMIN: &str = "PMCAuth:command.admin";

/// Argument keys used in the command trees.
///
/// `get_value` is keyed by node name, so nodes that are never present in the same
/// invocation may share a name.
const ARG_PASSWORD: &str = "password";
const ARG_CONFIRM: &str = "confirm";
const ARG_OLD_PASSWORD: &str = "old_password";
const ARG_NEW_PASSWORD: &str = "new_password";
const ARG_ACTION: &str = "action";
const ARG_PLAYER: &str = "player";

/// Commands a not-yet-authenticated player is allowed to run.
///
/// `/premium` is deliberately absent: linking requires an authenticated account.
pub const PUBLIC_COMMANDS: &[&str] = &["login", "register"];

/// Returns `true` when `command_line` (e.g. `"/login hunter2"`) may be executed by
/// a player who has not authenticated yet.
///
/// Also accepts the form without a leading slash, because the preprocess event
/// payload differs between clients.
pub fn is_public_command(command_line: &str) -> bool {
    // Trim whitespace first, then the slash: clients are inconsistent about both.
    let trimmed = command_line.trim().trim_start_matches('/');
    let mut parts = trimmed.split_whitespace();
    let Some(name) = parts.next() else {
        return false;
    };
    PUBLIC_COMMANDS
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

// --- argument helpers -----------------------------------------------------

/// Extracts a single-word string argument.
fn string_arg(args: &ConsumedArgs, key: &str) -> Option<String> {
    match args.get_value(key) {
        Arg::Simple(value) | Arg::Msg(value) => Some(value),
        _ => None,
    }
}

/// Sends a rendered auth reply to the command sender, in the sender's language.
///
/// The console has no locale, so it gets the default language.
fn reply(sender: &CommandSender, state: &AuthState, message: crate::auth::AuthReply) {
    let config = state.config();
    let locale = sender
        .as_player()
        .map_or_else(String::new, |player| player.get_locale());
    let text = message.render(config, &locale);
    sender.send_message(TextComponent::text(&text));
}

fn error(sender: &CommandSender, state: &AuthState, key: &'static str) {
    reply(sender, state, crate::auth::AuthReply::fail(key));
}

/// Resolves the player behind a command sender, or reports console-only misuse.
fn require_player(sender: &CommandSender, state: &AuthState) -> Option<pumpkin_plugin_api::Player> {
    match sender.as_player() {
        Some(player) => Some(player),
        None => {
            error(sender, state, "not_logged_in");
            None
        }
    }
}

// --- /register ------------------------------------------------------------

struct RegisterCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for RegisterCommand {
    fn handle(
        &self,
        sender: CommandSender,
        _server: Server,
        args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(player) = require_player(&sender, &self.0) else {
            return Ok(0);
        };
        let Some(password) = string_arg(&args, ARG_PASSWORD) else {
            error(&sender, &self.0, "register_prompt");
            return Ok(0);
        };
        let Some(confirm) = string_arg(&args, ARG_CONFIRM) else {
            error(&sender, &self.0, "register_prompt");
            return Ok(0);
        };

        let result = crate::auth::register(
            &self.0,
            &player.get_id().to_string(),
            &player.get_name(),
            &player.get_ip(),
            &password,
            &confirm,
        );

        reply(&sender, &self.0, result.clone());
        if result.key == "register_success" {
            crate::events::on_authenticated(&self.0, &player);
        }
        Ok(0)
    }
}

// --- /login ---------------------------------------------------------------

struct LoginCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for LoginCommand {
    fn handle(
        &self,
        sender: CommandSender,
        _server: Server,
        args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(player) = require_player(&sender, &self.0) else {
            return Ok(0);
        };
        let Some(password) = string_arg(&args, ARG_PASSWORD) else {
            error(&sender, &self.0, "login_prompt");
            return Ok(0);
        };

        let result = crate::auth::login(
            &self.0,
            &player.get_id().to_string(),
            &player.get_name(),
            &player.get_ip(),
            &password,
        );

        reply(&sender, &self.0, result.clone());
        if result.key == "login_success" {
            crate::events::on_authenticated(&self.0, &player);
        }
        Ok(0)
    }
}

// --- /logout --------------------------------------------------------------

struct LogoutCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for LogoutCommand {
    fn handle(
        &self,
        sender: CommandSender,
        _server: Server,
        _args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(player) = require_player(&sender, &self.0) else {
            return Ok(0);
        };

        let result = crate::auth::logout(&self.0, &player.get_id().to_string(), &player.get_ip());
        let logged_out = result.key == "logout_success";

        reply(&sender, &self.0, result);
        if logged_out {
            crate::events::on_deauthenticated(&self.0, &player);
        }
        Ok(0)
    }
}

// --- /changepassword ------------------------------------------------------

struct ChangePasswordCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for ChangePasswordCommand {
    fn handle(
        &self,
        sender: CommandSender,
        _server: Server,
        args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(player) = require_player(&sender, &self.0) else {
            return Ok(0);
        };
        let Some(old_password) = string_arg(&args, ARG_OLD_PASSWORD) else {
            error(&sender, &self.0, "internal_error");
            return Ok(0);
        };
        let Some(new_password) = string_arg(&args, ARG_NEW_PASSWORD) else {
            error(&sender, &self.0, "internal_error");
            return Ok(0);
        };

        let result = crate::auth::change_password(
            &self.0,
            &player.get_id().to_string(),
            &player.get_name(),
            &old_password,
            &new_password,
        );

        reply(&sender, &self.0, result);
        Ok(0)
    }
}

// --- /authadmin -----------------------------------------------------------

struct AuthAdminCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for AuthAdminCommand {
    fn handle(
        &self,
        sender: CommandSender,
        server: Server,
        args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(action) = string_arg(&args, ARG_ACTION) else {
            error(&sender, &self.0, "admin_usage");
            return Ok(0);
        };
        let Some(target) = string_arg(&args, ARG_PLAYER) else {
            error(&sender, &self.0, "admin_usage");
            return Ok(0);
        };

        let target_lc = lowercase(&target);

        match action.as_str() {
            "unregister" => {
                let result = crate::auth::admin_unregister(&self.0, &target_lc);
                reply(&sender, &self.0, result);
            }
            "forcelogin" => {
                // Prefer the live player handle; fall back to a stored UUID lookup.
                let Some(player) = server.get_player_by_name(&target) else {
                    error(&sender, &self.0, "admin_player_offline");
                    return Ok(0);
                };
                let result = crate::auth::admin_force_login(
                    &self.0,
                    &player.get_id().to_string(),
                    &player.get_ip(),
                );
                reply(&sender, &self.0, result.clone());
                if result.key == "admin_done" {
                    crate::events::on_authenticated(&self.0, &player);
                }
            }
            "setpassword" => {
                let Some(new_password) = string_arg(&args, ARG_NEW_PASSWORD) else {
                    error(&sender, &self.0, "admin_usage");
                    return Ok(0);
                };
                let result = crate::auth::admin_set_password(&self.0, &target_lc, &new_password);
                reply(&sender, &self.0, result);
            }
            _ => error(&sender, &self.0, "admin_usage"),
        }

        Ok(0)
    }
}

// --- /premium and /cracked ------------------------------------------------

/// Links the calling player's own account, reading the trust anchor from the
/// live connection so a claim can never come from the command itself.
fn link_own_account(
    state: &AuthState,
    server: &Server,
    player: &pumpkin_plugin_api::Player,
) -> crate::auth::AuthReply {
    let anchor = premium_anchor(state, server, player);
    let has_textures = player.get_skin().is_some();
    crate::auth::premium_link(
        state,
        &player.get_id().to_string(),
        &player.get_name(),
        anchor,
        has_textures,
    )
}

struct PremiumCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for PremiumCommand {
    fn handle(
        &self,
        sender: CommandSender,
        server: Server,
        _args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(player) = require_player(&sender, &self.0) else {
            return Ok(0);
        };

        let result = link_own_account(&self.0, &server, &player);
        reply(&sender, &self.0, result);
        Ok(0)
    }
}

struct PremiumOffCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for PremiumOffCommand {
    fn handle(
        &self,
        sender: CommandSender,
        _server: Server,
        _args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(player) = require_player(&sender, &self.0) else {
            return Ok(0);
        };

        let result = crate::auth::premium_unlink(&self.0, &player.get_id().to_string());
        reply(&sender, &self.0, result);
        Ok(0)
    }
}

struct PremiumStatusCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for PremiumStatusCommand {
    fn handle(
        &self,
        sender: CommandSender,
        _server: Server,
        _args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(player) = require_player(&sender, &self.0) else {
            return Ok(0);
        };

        let result =
            crate::auth::premium_status(&self.0, &player.get_id().to_string(), &player.get_name());
        reply(&sender, &self.0, result);
        Ok(0)
    }
}

/// `/authadmin premium set <player>` — binds the target's *current* session UUID.
struct AdminPremiumSetCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for AdminPremiumSetCommand {
    fn handle(
        &self,
        sender: CommandSender,
        server: Server,
        args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(target) = string_arg(&args, ARG_PLAYER) else {
            error(&sender, &self.0, "admin_usage");
            return Ok(0);
        };

        // The bound UUID is the connection UUID, so the player has to be online.
        let Some(player) = server.get_player_by_name(&target) else {
            error(&sender, &self.0, "premium_admin_requires_online");
            return Ok(0);
        };

        let anchor = premium_anchor(&self.0, &server, &player);
        let has_textures = player.get_skin().is_some();
        let result =
            crate::auth::admin_premium_set(&self.0, &lowercase(&target), anchor, has_textures);
        reply(&sender, &self.0, result);
        Ok(0)
    }
}

/// `/authadmin premium unset <player>` — stored account only, works offline.
struct AdminPremiumUnsetCommand(Arc<AuthState>);

impl pumpkin_plugin_api::commands::CommandHandler for AdminPremiumUnsetCommand {
    fn handle(
        &self,
        sender: CommandSender,
        _server: Server,
        args: ConsumedArgs,
    ) -> Result<i32, CommandError> {
        let Some(target) = string_arg(&args, ARG_PLAYER) else {
            error(&sender, &self.0, "admin_usage");
            return Ok(0);
        };

        let result = crate::auth::admin_premium_unset(&self.0, &lowercase(&target));
        reply(&sender, &self.0, result);
        Ok(0)
    }
}

// --- registration ---------------------------------------------------------

/// Registers the permission nodes the plugin needs.
pub fn register_permissions(context: &Context) -> pumpkin_plugin_api::Result<()> {
    let permissions = [
        (PERM_REGISTER, "Allows /register", PermissionDefault::Allow),
        (PERM_LOGIN, "Allows /login", PermissionDefault::Allow),
        (PERM_LOGOUT, "Allows /logout", PermissionDefault::Allow),
        (
            PERM_CHANGEPASSWORD,
            "Allows /changepassword",
            PermissionDefault::Allow,
        ),
        (
            PERM_PREMIUM,
            "Allows /premium and /cracked",
            PermissionDefault::Allow,
        ),
        (
            PERM_ADMIN,
            "Allows /authadmin",
            PermissionDefault::Op(pumpkin_plugin_api::permission::PermissionLevel::Three),
        ),
    ];

    for (node, description, default) in permissions {
        context.register_permission(&Permission {
            node: node.to_string(),
            description: description.to_string(),
            default,
            children: Vec::new(),
        })?;
    }

    Ok(())
}

/// Builds and registers every command tree.
pub fn register_commands(
    context: &Context,
    state: Arc<AuthState>,
) -> pumpkin_plugin_api::Result<()> {
    context.register_command(build_register(state.clone()), PERM_REGISTER);
    context.register_command(build_login(state.clone()), PERM_LOGIN);
    context.register_command(build_logout(state.clone()), PERM_LOGOUT);
    context.register_command(build_change_password(state.clone()), PERM_CHANGEPASSWORD);
    context.register_command(build_premium(state.clone()), PERM_PREMIUM);
    context.register_command(build_cracked(state.clone()), PERM_PREMIUM);
    context.register_command(build_auth_admin(state), PERM_ADMIN);
    Ok(())
}

fn string_node(name: &'static str) -> CommandNode {
    CommandNode::argument(
        name,
        &pumpkin_plugin_api::command::ArgumentType::String(
            pumpkin_plugin_api::command::StringType::SingleWord,
        ),
    )
}

fn build_register(state: Arc<AuthState>) -> Command {
    let node = string_node(ARG_CONFIRM).execute(RegisterCommand(state));
    let password = string_node(ARG_PASSWORD).then(node);
    let command = Command::new(&["register".to_string()], "Create an account");
    command.then(password)
}

fn build_login(state: Arc<AuthState>) -> Command {
    let command = Command::new(&["login".to_string()], "Log in to your account");
    command.then(string_node(ARG_PASSWORD).execute(LoginCommand(state)))
}

fn build_logout(state: Arc<AuthState>) -> Command {
    let command = Command::new(&["logout".to_string()], "Log out");
    command.execute(LogoutCommand(state))
}

fn build_change_password(state: Arc<AuthState>) -> Command {
    let node = string_node(ARG_NEW_PASSWORD).execute(ChangePasswordCommand(state));
    let old = string_node(ARG_OLD_PASSWORD).then(node);
    let command = Command::new(
        &["changepassword".to_string(), "changepw".to_string()],
        "Change your password",
    );
    command.then(old)
}

fn build_premium(state: Arc<AuthState>) -> Command {
    // Each literal branch gets its own handler: the host only records *argument*
    // nodes in `ConsumedArgs`, so a literal's text is not readable with
    // `get_value("action")`. Branching inside one handler would see nothing.
    let command = Command::new(
        &["premium".to_string()],
        "Enable premium (Mojang) login for your account",
    );
    let command = command.execute(PremiumCommand(state.clone()));
    let command =
        command.then(CommandNode::literal("off").execute(PremiumOffCommand(state.clone())));
    command.then(CommandNode::literal("status").execute(PremiumStatusCommand(state)))
}

fn build_cracked(state: Arc<AuthState>) -> Command {
    Command::new(
        &["cracked".to_string()],
        "Disable premium login and use your password again",
    )
    .execute(PremiumOffCommand(state))
}

fn build_auth_admin(state: Arc<AuthState>) -> Command {
    let unregister = CommandNode::literal("unregister")
        .then(string_node(ARG_PLAYER).execute(AuthAdminCommand(state.clone())));
    let forcelogin = CommandNode::literal("forcelogin")
        .then(string_node(ARG_PLAYER).execute(AuthAdminCommand(state.clone())));

    let set_password = CommandNode::literal("setpassword").then(
        string_node(ARG_PLAYER)
            .then(string_node(ARG_NEW_PASSWORD).execute(AuthAdminCommand(state.clone()))),
    );

    let premium = CommandNode::literal("premium")
        .then(
            CommandNode::literal("set")
                .then(string_node(ARG_PLAYER).execute(AdminPremiumSetCommand(state.clone()))),
        )
        .then(
            CommandNode::literal("unset")
                .then(string_node(ARG_PLAYER).execute(AdminPremiumUnsetCommand(state))),
        );

    let command = Command::new(&["authadmin".to_string()], "PMCAuth administration");
    let command = command.then(unregister);
    let command = command.then(forcelogin);
    let command = command.then(set_password);
    command.then(premium)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_use_the_plugin_namespace() {
        // `Context::register_permission` rejects any other prefix, case-sensitively.
        for node in [
            PERM_REGISTER,
            PERM_LOGIN,
            PERM_LOGOUT,
            PERM_CHANGEPASSWORD,
            PERM_ADMIN,
        ] {
            assert!(
                node.starts_with(&format!("{}:", crate::PLUGIN_NAME)),
                "{node} must start with \"{}:\"",
                crate::PLUGIN_NAME
            );
        }
    }

    #[test]
    fn login_and_register_are_public() {
        assert!(is_public_command("/login hunter2"));
        assert!(is_public_command("/register pass pass"));
        assert!(is_public_command("login hunter2"));
        assert!(is_public_command("  /LOGIN  hunter2 "));
    }

    #[test]
    fn everything_else_is_blocked() {
        assert!(!is_public_command("/gamemode creative"));
        assert!(!is_public_command("/logout"));
        assert!(!is_public_command(""));
        assert!(!is_public_command("/"));
        // A prefix must not be accepted just because it starts with "login".
        assert!(!is_public_command("/loginx hunter2"));
    }
}
