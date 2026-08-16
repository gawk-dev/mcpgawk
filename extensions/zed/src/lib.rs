//! mcpgawk for Zed — registers the auditor as a context server.
//!
//! WHAT THIS IS, STATED PLAINLY: Zed's extension API (verified against `zed_extension_api` 0.7)
//! exposes language servers, slash commands, context servers and docs indexing — and no panel, tree
//! or view surface of any kind. The fleet panel that the VS Code and JetBrains surfaces render is
//! therefore impossible here, for ANY extension, not just this one.
//!
//! So this is NOT a third port of the panel. It makes mcpgawk available to Zed's agent as a tool it
//! can call — "what MCP servers do I have, and what can they do to me?" — and the answer arrives as
//! conversation, not as a grouped list with states and actions. That is a materially smaller
//! product than the other two surfaces, and describing the three as equivalent would be untrue.
//!
//! The extension is deliberately thin. It resolves a command and hands it to Zed; all scanning,
//! measurement and verdict logic lives in the Python engine, exactly as it does for the VS Code
//! extension. Nothing here decides whether a server is safe.

use std::collections::HashMap;

use zed_extension_api::{
    self as zed, settings::ContextServerSettings, Command, ContextServerId, Project, Result,
};

/// Shipped as an entry point rather than a bare module path so a user who installed with pipx or a
/// virtualenv gets the same binary the CLI uses.
const DEFAULT_COMMAND: &str = "mcpgawk-mcp";

/// The install roots the engine actually lands in, prepended to PATH before the exec below.
const INSTALL_ROOTS: &str = "$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:$HOME/.cargo/bin";

/// What Zed is asked to spawn, and how.
///
/// MEASURED, not assumed: with Zed's own environment (`PATH=/usr/bin:/bin:/usr/sbin:/sbin`, what a
/// GUI-launched macOS app inherits) the bare name fails outright —
/// `env: mcpgawk-mcp: No such file or directory` — and Zed surfaces that as
/// "Context server failed to start: Context server request timeout", which points the user at
/// slowness rather than at a PATH they cannot see. The handshake itself takes 0.41s, so a timeout
/// was never the real story.
///
/// Zed's extension API cannot help here: `Worktree::which()` and `shell_env()` exist, but a worktree
/// is only handed to LANGUAGE SERVER callbacks — a context server receives a `Project`, which
/// exposes worktree ids and nothing else. So the resolution has to live in the command.
///
/// A LOGIN SHELL is deliberately not used. `/bin/sh -lc` reads `/etc/profile` and `~/.profile`,
/// which on a zsh machine is not where `~/.local/bin` gets added — it would work by accident or not
/// at all. Prepending the known roots explicitly is deterministic and needs no shell config.
///
/// `exec` matters: it replaces the shell rather than leaving it as a parent, so stdio and signals
/// reach the server directly. An MCP server speaks over stdin/stdout, and an extra process in the
/// middle is a way to lose both.
fn resolve_invocation(configured: Option<&str>) -> (String, Vec<String>) {
    if let Some(path) = configured.map(str::trim).filter(|p| !p.is_empty()) {
        // An explicitly configured path is used verbatim. The user has told us exactly where the
        // binary is; wrapping it in a shell would only add a way for their answer to be wrong.
        return (path.to_string(), Vec::new());
    }
    (
        "/bin/sh".to_string(),
        vec![
            "-c".to_string(),
            format!("PATH=\"{INSTALL_ROOTS}:$PATH\"; exec {DEFAULT_COMMAND}"),
        ],
    )
}

/// Settings-supplied arguments, appended after whatever the invocation itself needs. The engine
/// requires no flags to serve MCP; this exists so a user can add their own without rebuilding.
fn resolve_args(base: Vec<String>, configured: Option<Vec<String>>) -> Vec<String> {
    let mut args = base;
    args.extend(configured.unwrap_or_default());
    args
}

/// Environment for the child. Empty unless the user asked otherwise: the engine reads the user's
/// own config files, and handing it an environment we assembled would obscure what it actually ran
/// with. A user who needs one (a proxy, a token) sets it explicitly.
fn resolve_env(configured: Option<HashMap<String, String>>) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = configured.unwrap_or_default().into_iter().collect();
    // Deterministic order: an env that reshuffles per launch makes two runs hard to compare.
    env.sort();
    env
}

struct McpgawkExtension;

impl zed::Extension for McpgawkExtension {
    fn new() -> Self {
        Self
    }

    fn context_server_command(
        &mut self,
        context_server_id: &ContextServerId,
        project: &Project,
    ) -> Result<Command> {
        // Settings are advisory: if they cannot be read we still start with the default rather than
        // refusing to run. A missing setting must never be the reason the auditor is unavailable.
        let configured = ContextServerSettings::for_project(context_server_id.as_ref(), project)
            .ok()
            .and_then(|s| s.command);

        let (path, args, env) = match configured {
            Some(c) => (c.path, c.arguments, c.env),
            None => (None, None, None),
        };

        let (command, base_args) = resolve_invocation(path.as_deref());
        Ok(Command {
            command,
            args: resolve_args(base_args, args),
            env: resolve_env(env),
        })
    }
}

zed::register_extension!(McpgawkExtension);

/// These run on the HOST (`cargo test`), not in wasm — they cover the pure resolution rules, which
/// is the only logic this extension has. It previously had no tests at all, so nothing checked even
/// that the command name matches the one the install docs tell people to install.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_invocation_puts_the_install_roots_on_path() {
        // The defect this fixes, exactly: with Zed's own environment
        // (PATH=/usr/bin:/bin:/usr/sbin:/sbin) the bare name fails with
        // "env: mcpgawk-mcp: No such file or directory", and Zed reports it as a request TIMEOUT —
        // sending the user to debug slowness in a server whose handshake takes 0.41s.
        let (cmd, args) = resolve_invocation(None);
        assert_eq!(cmd, "/bin/sh");
        let script = args.last().expect("a script argument");
        assert!(script.contains("$HOME/.local/bin"), "uv tool / pipx install root missing");
        assert!(script.contains("/opt/homebrew/bin"));
        assert!(script.contains("$PATH"), "must PREPEND, never replace, the inherited PATH");
        assert!(script.contains(DEFAULT_COMMAND));
    }

    #[test]
    fn the_default_invocation_execs_so_stdio_reaches_the_server() {
        // Without exec the shell stays as a parent process, between Zed and an MCP server that
        // speaks over stdin/stdout. That is a way to lose the protocol and the signals.
        let (_, args) = resolve_invocation(None);
        assert!(args.last().unwrap().contains(&format!("exec {DEFAULT_COMMAND}")));
    }

    #[test]
    fn an_explicit_path_is_run_verbatim_with_no_shell() {
        // The user has said precisely where the binary is; wrapping that in a shell only adds a way
        // for their answer to be misread.
        let (cmd, args) = resolve_invocation(Some("/opt/venv/bin/mcpgawk-mcp"));
        assert_eq!(cmd, "/opt/venv/bin/mcpgawk-mcp");
        assert!(args.is_empty());
    }

    #[test]
    fn a_blank_setting_falls_back_instead_of_running_an_empty_command() {
        // Clearing the field in settings.json leaves "". Spawning that fails with a message about a
        // command named nothing, which sends the user somewhere useless.
        assert_eq!(resolve_invocation(Some("")).0, "/bin/sh");
        assert_eq!(resolve_invocation(Some("   ")).0, "/bin/sh");
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_the_path() {
        assert_eq!(resolve_invocation(Some(" /usr/bin/x \n")).0, "/usr/bin/x");
    }

    #[test]
    fn no_arguments_are_added_on_the_users_behalf() {
        // Nothing here may add a flag. In the sibling surfaces the flag that matters is `--yes`,
        // which LAUNCHES local servers, i.e. runs their code. This extension must never supply it.
        let (_, base) = resolve_invocation(Some("/bin/mcpgawk-mcp"));
        let args = resolve_args(base, None);
        assert!(args.is_empty());
        assert!(!args.iter().any(|a| a == "--yes"));
    }

    #[test]
    fn the_default_invocation_never_smuggles_in_a_launch_flag() {
        let (_, args) = resolve_invocation(None);
        assert!(!args.iter().any(|a| a.contains("--yes")));
    }

    #[test]
    fn user_arguments_are_appended_after_the_invocation_itself() {
        let (_, base) = resolve_invocation(Some("/bin/mcpgawk-mcp"));
        let args = resolve_args(base, Some(vec!["--only".into(), "figma".into()]));
        assert_eq!(args, vec!["--only", "figma"]);
    }

    #[test]
    fn the_environment_is_empty_unless_the_user_set_one() {
        assert!(resolve_env(None).is_empty());
    }

    #[test]
    fn user_environment_is_passed_in_a_stable_order() {
        let mut given = HashMap::new();
        given.insert("B".to_string(), "2".to_string());
        given.insert("A".to_string(), "1".to_string());
        assert_eq!(
            resolve_env(Some(given)),
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "2".to_string())
            ]
        );
    }
}
