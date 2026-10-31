# PMCAuth

AuthMe-style authentication plugin for [Pumpkin MC](https://github.com/Pumpkin-MC/Pumpkin).
Players must `/register` or `/login` before they can play. Accounts are stored in a
JSON file inside the plugin's private data folder; passwords are Argon2id hashes.

## Status

- `cargo build --release` passes, artefact `target/wasm32-wasip2/release/pmc_auth.wasm` (962 KiB / 984,677 bytes).
- `cargo test --target x86_64-unknown-linux-gnu` — 55 tests pass.
- Pinned to a `pumpkin-plugin-api` git rev (WIT `pumpkin:plugin@0.1.0`); see `Cargo.toml`.

## Plugin ABI: v0.1 vs v0.2

Pumpkin ships **two** plugin ABIs at the same time, and the server has a loader for
each (`crates/pumpkin-wasm-host-v0_1` and `pumpkin-wasm-host-v0_2`). It picks one by
the package version baked into the `.wasm` component:

| ABI | Package | Exports | Host crate |
|---|---|---|---|
| v0.1 | `pumpkin:plugin@0.1.0` | synchronous | `pumpkin-wasm-host-v0_1` |
| v0.2 | `pumpkin:plugin@0.2.0` | **async** (`on-load`, `handle-event`, … are `async func`) | `pumpkin-wasm-host-v0_2` |

A mismatch shows up as:

```
Wasm plugin initialization error:
Plugin was built against a different iteration of the API:
type-checking export func `handle-event`
```

`pumpkin-plugin-api` on crates.io publishes **only the v0.1 ABI**. Its WIT is
byte-identical to Pumpkin master's `crates/pumpkin-plugin-wit/v0.1/*.wit`, verified
with `diff` on `event`, `player`, `command`, `context`, `server`, `text`, `common`
and `plugin`.

### If the plugin stops loading after a server update

Check which host the server uses. If the log names `v0_2`, or the component needs
`async func` exports, this crate cannot target it — there is no async-ABI build of
`pumpkin-plugin-api` on crates.io yet. Options, in order of effort:

1. Pin the server to a build that still ships `pumpkin-wasm-host-v0_1` (current one does).
2. Depend on Pumpkin's `crates/pumpkin-plugin-api` from git instead of crates.io:
   `pumpkin-plugin-api = { git = "https://github.com/Pumpkin-MC/Pumpkin" }`.
3. Port the handlers to `async` against the v0.2 WIT.

Do not guess a version number from the release string. `+26.3-26.60` and
`+26.3-26.51` are the *same* semver version (`0.2.1`) to Cargo — the `+...` build
metadata is ignored. Only the WIT content matters.

### Confirmed: no Rust crate can target v0.2 today

Verified against Pumpkin master on 2026-10-31:

- `crates/pumpkin-plugin-api/src/lib.rs` still generates from
  `path: "../pumpkin-plugin-wit/v0.1"`.
- crates.io has exactly three `pumpkin-plugin-api` versions, all v0.1 WIT.
- `crates/pumpkin-wasm-host-v0_2` is the **host** side only.

So "port to 0.2" means writing guest bindings from the v0.2 WIT, not bumping a
version string. Full analysis, the exact v0.1→v0.2 diff, and a cheap spike that
decides whether it is even feasible are in [`docs/ABI-v0.2-port.md`](docs/ABI-v0.2-port.md).
Run the spike before committing to a port.

### Quickest ways to get the plugin running

1. Use a server build that ships `pumpkin-wasm-host-v0_1` (the v0.1 loader). The
   plugin's WIT is byte-identical to master's v0.1, so it loads.
2. Build Pumpkin yourself with the `plugin-v0_2` feature off.
3. Port (see the doc). Highest cost, only sensible after the spike passes.

## Build

```bash
rustup target add wasm32-wasip2
cargo build --release
```

No WASI SDK is required: nothing in the dependency tree compiles C.

`.cargo/config.toml` already pins `target = "wasm32-wasip2"`, so plain
`cargo build --release` produces the plugin.

## Install

```bash
mkdir -p <server>/plugins
cp target/wasm32-wasip2/release/pmc_auth.wasm <server>/plugins/
```

On first start the plugin creates:

```
<server>/plugins/data/PMCAuth/
├── config.toml     # generated from config.default.toml
├── users.json      # created on load, even before the first registration
└── config.toml.broken  # only if an unparseable config was replaced
```

`config.toml` is regenerated automatically: delete it and the next start writes a
fresh default. If the file exists but cannot be parsed, it is renamed to
`config.toml.broken` and a working default is written in its place, so a typo
never leaves the plugin running on invisible settings. The parse error is still
logged, and the active settings fall back to built-in defaults for that run.

The plugin requests `fs.read.data` and `fs.write.data`. Without those permissions
the host does not preopen the data folder and the plugin cannot start.

## Languages

Messages are answered in each player's own client language. English (`en`) is the
default and Indonesian (`id`) is built in; any other locale falls back to English.

Messages live per language in `config.toml`:

```toml
[messages.en]
login_success = "Login successful. Have fun!"

[messages.id]
login_success = "Login berhasil. Selamat bermain!"
```

- Only the keys you list are overridden. Everything else, and any deleted line,
  comes from the built-in defaults for that language.
- Add a language by adding a table such as `[messages.de]` and translating the
  values. It is used when a client reports `de`, `de_de`, `de-DE`, and so on;
  languages with no table at all fall back to English.
- Adding a new language in code requires one entry in `BUILTIN_MESSAGES` plus a
  match arm in `language_of` (see [`src/config.rs`](src/config.rs:1)).
- A `config.toml` written by an older version with a flat `[messages]` table still
  loads: its strings are read as the English messages, so existing wording is kept.

## Commands

| Command | Permission | Default |
|---|---|---|
| `/register <password> <confirm>` | `PMCAuth:command.register` | everyone |
| `/login <password>` | `PMCAuth:command.login` | everyone |
| `/logout` | `PMCAuth:command.logout` | everyone |
| `/changepassword <old> <new>` (alias `/changepw`) | `PMCAuth:command.changepassword` | everyone |
| `/authadmin unregister <player>` | `PMCAuth:command.admin` | op level 3 |
| `/authadmin forcelogin <player>` | `PMCAuth:command.admin` | op level 3 |
| `/authadmin setpassword <player> <password>` | `PMCAuth:command.admin` | op level 3 |

## What an unauthenticated player cannot do

Movement is frozen natively via `Player::set_movement_locked(true)`. On top of that,
these events are cancelled until the player authenticates:

`PlayerMoveEvent`, `PlayerChatEvent`, `PlayerCommandPreprocessEvent` (except `/login`
and `/register`), `PlayerInteractEvent`, `PlayerInteractEntityEvent`,
`PlayerInteractAtEntityEvent`, `BlockBreakEvent`, `BlockPlaceEvent`,
`PlayerDropItemEvent`, `PlayerItemConsumeEvent`, `InventoryClickEvent`,
`InventoryOpenEvent`.

## Storage design

`users.json`:

```json
{
  "schema_version": 1,
  "next_id": 2,
  "users": [
    {
      "id": 1,
      "username": "Notch",
      "username_lc": "notch",
      "uuid": "…",
      "password_hash": "$argon2id$v=19$m=8192,t=2,p=1$…",
      "registered_ip": "203.0.113.7",
      "last_ip": "203.0.113.7",
      "registered_at": 1793432503,
      "last_login": 1793432503,
      "login_failures": 0
    }
  ]
}
```

- `username_lc` is the lookup key, so usernames are case-insensitive and unique.
- Writes go to `<database>.tmp` (e.g. `users.json.tmp`) and are then renamed, so a
  crash mid-write cannot truncate the database.
- The whole table is held in memory; lookups are O(1) hashmap hits. This is why
  database access never blocks the game loop.
- `schema_version` replaces `PRAGMA user_version`. `FileStore::migrate` refuses to
  load a version it does not understand rather than silently misreading accounts.

### Why not SQLite

`rusqlite` *can* target `wasm32-wasip2`, but only with `bundled` +
`wasm32-wasi-vfs`, which requires the WASI SDK (SQLite is C). The bundled VFS
registers `sqlite3_io_methods` **version 1** — no `xShmMap`, no file locking — so
`journal_mode=WAL` is impossible, and temp files need `temp_store=MEMORY`.

For a table with one row per registered player, a JSON file costs no extra
toolchain, adds ~0 to the binary, and is fast enough. `UserStore` is a trait, so a
SQLite backend can be added later without touching `auth.rs`.

## Concurrency and blocking

The server main thread calls into the plugin for every event. The rules that keep
that cheap:

1. All account data lives in memory behind one `Mutex`.
2. Every handler takes the lock, copies what it needs, drops the guard, and only
   then calls a host API (`send_message`, `kick`, `set_movement_locked`).
   Pumpkin's docs warn that a host call can re-enter the plugin synchronously, so
   holding a guard across one would deadlock.
3. The one genuinely expensive operation is Argon2. It runs inline on purpose:
   the sandbox is single-threaded and there is no async password API. Cost is
   configurable in `[argon2]`; the defaults (8 MiB, 2 iterations) keep login
   latency in the low tens of milliseconds.

## Security notes

- Argon2id, unique random salt per user, salt stored inside the PHC string.
- `verify_password` is constant-time inside the `argon2` crate.
- Wrong password and unknown account produce **identical** messages
  (`login_failed` and `not_registered` both render "Login gagal.").
- When the account does not exist, a dummy hash is verified anyway so response
  time does not reveal whether a username is registered.
- Password policy: minimum/maximum length and "must not equal the username".
- Passwords are never logged and never included in error messages by the plugin.
- Brute force: `login_failures` is persisted per account; reaching
  `max_login_attempts` locks the UUID out for `lockout_seconds`.

### Passwords in the server console (not fixable from a plugin)

A plugin cannot hide `/login` and `/register` passwords from the server console.
This is a limitation of the host, not something PMCAuth can work around, and it is
worth understanding before you assume the passwords are safe.

What happens today on a Pumpkin `0.2.1+26.3-26.60` server:

1. The only command event the server fires is `PlayerCommandSendEvent`.
   `PlayerCommandPreprocessEvent` exists in the WIT/API but **is never fired** —
   the command is handled directly after the send event.
2. After that event, the server runs, roughly:

   ```rust
   let command = event.command;                              // the event's own string
   dispatcher.handle_command(&source, &command);             // re-parsed from this string
   if server.advanced_config.commands.log_console {
       info!("Player ({}): executed command /{}", name, command);
   }
   ```

3. The string that gets logged is the same string that gets **parsed and executed**.
   Masking it in the plugin (`/login ***`) would hand `***` to the parser and break
   `/login` itself. Redaction and execution are the same value, so there is no
   point where the plugin can see the real password and the server only a masked one.
4. There is no per-command setting to disable logging for individual commands, and
   upstream has no password-masking helper.

Residual exposures, including ones this plugin cannot prevent:

| Exposure | Can PMCAuth prevent it? |
|---|---|
| `commands.log_console = true` writes `Player (name): executed command /login hunter2` | No — turn the setting off (below) |
| A password typed **in the server console** itself (e.g. `/authadmin setpassword`) is echoed by the terminal and by the console reader | No |
| Command text passed to the plugin logging/IPC API by the server or another plugin | No |
| PMCAuth's own messages, replies and error text | Yes — it never includes the password |

**Recommended server configuration.** This goes in Pumpkin's own server config,
`pumpkin.toml` at the server root — not in PMCAuth's `config.toml`. `advanced` is
flattened into the root, so `[commands]` is a top-level table:

```toml
[commands]
# Off: do not write every player command to the console. This removes the
# "Player (name): executed command /login <password>" line for all commands,
# including the ones that carry credentials.
log_console = false
```

The same table already exists in a generated `pumpkin.toml`; edit the value rather
than adding a second `[commands]` block, and restart the server afterwards.

Trade-offs to accept when you turn this off:

- You lose an audit trail of what players run. For most auth-heavy servers that is
  a good trade; if you need the trail, do not use password-carrying commands.
- The console is still readable by whoever operates the server, and console input
  is still echoed. Do not run `/authadmin setpassword` from a console that other
  people can read; prefer `/authadmin setpassword` from an in-game op, and change
  the password afterwards if it was ever typed into a shared console.
- If `commands.log_console` is true and a player's password appears in the log
  file, treat that password as compromised: ask the player to run
  `/changepassword`, and remember Argon2 protects the *stored* hash, not a
  password that was written to disk in plaintext.

Re-check this if you upgrade the server: the moment upstream fires
`PlayerCommandPreprocessEvent` before dispatch, or logs a separately-masked string,
a plugin-side redaction becomes possible and this note is obsolete.

## Manual test checklist

1. `/plugins` lists PMCAuth; `plugins/data/PMCAuth/` exists with `config.toml` and `users.json`.
2. Fresh player joins → frozen, receives the register + login prompts, cannot move/chat/mine.
3. `/register abc abc` → length error. `/register password password` → success.
4. `/register password password` again → "already registered".
5. Relog → not logged in. `/login wrong` → generic failure. Relog time is roughly the
   same as for an unregistered name.
6. `/login password` → can move, chat, mine, open containers.
7. Run `/gamemode creative` before logging in → denied by the command guard.
8. Fail `/login` `max_login_attempts` times → account locked; further attempts report
   the lockout instead of "wrong password".
9. With `[commands] log_console = false` in `pumpkin.toml`, run `/login <password>` and
   confirm the console prints no `executed command /login ...` line. If it still does,
   the setting did not take effect — check for a duplicate `[commands]` block.
9. Join and idle for `login_timeout_seconds` → kicked with the timeout message.
   Set `kick_on_timeout = false` → the player stays frozen and gets re-prompted instead.
10. Set `session_minutes = 5`, log in, relog from the same IP → auto-authenticated.
    Set it back to `0` → relog requires the password again.
11. `/changepassword wrong new` → refused. `/changepassword password new` → ok;
    relog with `new`.
12. Non-op runs `/authadmin unregister x` → permission denied.
13. Op runs all three `/authadmin` subcommands against a target player.
14. Two players try the same name with different casing → the second is refused.
15. **Stop the server, restart, `/login new` → account survived** (proves the file store works).
16. Corrupt `users.json` deliberately (`echo garbage > users.json`) → plugin logs the
    parse error and refuses to start rather than wiping accounts.

## Known gaps

These are platform limits, not unfinished work:

1. **Passwords appear in the server console log.** `/login <password>` reaches the
   host as a normal command. Pumpkin exposes no pre-log hook and no client GUI input
   for secrets, so this cannot be hidden. AuthMe hides it with a GUI/captcha; that
   path does not exist here.
2. **Player-vs-entity attacks may not be blockable.** The API exposes
   `PlayerInteractEntityEvent` / `PlayerInteractAtEntityEvent`, and both are cancelled
   above, but whether a left-click attack fires them has **not been verified on a live
   server**. If it does not, an unauthenticated player could still hit mobs/players.
   Everything else (blocks, chat, commands, movement, inventories, item use, drops)
   is covered by a dedicated cancellable event.
3. **No async hashing.** Plugin callbacks are synchronous and the sandbox is
   single-threaded.
4. **No MaxMind/IP-range restrictions, name blacklists, or sub-account limits.**
   Out of scope.
5. **Only the v0.1 ABI is available on crates.io.** If a future Pumpkin server drops
   `pumpkin-wasm-host-v0_1`, this plugin stops loading and must be ported to the
   async v0.2 ABI (see the ABI section above).

## Source layout

```
src/
├── lib.rs                 Plugin impl, on_load/on_unload, maintenance task, kick helper
├── config.rs              Config structs, defaults, load/sanitize
├── security.rs            Password policy, Argon2id hash/verify, dummy hash
├── auth.rs                register/login/logout/changepassword/admin rules (no API calls)
├── commands.rs            Command trees + CommandHandler impls
├── state.rs               AuthState: config, store, sessions, IP sessions, lockouts
├── storage/
│   ├── mod.rs             UserRecord, UserStore trait, StoreError
│   └── file_store.rs      JSON backend, atomic write, schema versioning
└── events/
    ├── mod.rs             Registration + on_authenticated / on_deauthenticated
    ├── join_leave.rs      Join (freeze, IP session check), leave (cleanup)
    └── guard.rs           The not-logged-in cancellations
```

`auth.rs` contains no Pumpkin API calls at all, which is what makes the rules
testable on the host.
