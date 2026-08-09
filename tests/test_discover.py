"""SCAN / Discovery — zero-config discovery of MCP servers across IDE clients.

Locks the behaviours that make `mcpgawk scan` (no args) just work: each client shape is found, Claude
Code's per-project nesting is flattened, parsing tolerates comments/trailing commas WITHOUT corrupting
`https://` urls, servers are deduped by launch identity, and a missing/malformed config is skipped,
never crashed on. `home`/`platform` are injected so this runs against a temp tree, not the real machine.
"""
from __future__ import annotations

import json
from pathlib import Path

from mcpgawk.discover import detect_unscannable, discover_servers


def _write(home: Path, rel: str, obj) -> None:
    p = home / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")


def _discover(home: Path):
    return discover_servers(home=home, platform="darwin")


def test_finds_plain_mcpservers_shape(tmp_path):
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "server-fs"]}}})
    got = _discover(tmp_path)
    assert "fs" in got and got["fs"]["command"] == "npx"


def test_same_command_different_env_are_two_servers(tmp_path):
    """Same binary, different credentials is a DIFFERENT server.

    Two GitHub orgs, two Slack workspaces, dev vs prod — identical command and args, pointed at
    different data. Identity ignored `env`, so the second collapsed into the first: never scanned,
    never baselined, therefore never guarded, while the fleet list implied it was covered. Found by
    planting 33 servers that differed only by env and watching them render as one.
    """
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {
        "gh-work": {"command": "npx", "args": ["-y", "gh-mcp"], "env": {"GITHUB_TOKEN": "work"}},
        "gh-personal": {"command": "npx", "args": ["-y", "gh-mcp"],
                        "env": {"GITHUB_TOKEN": "personal"}},
    }})

    got = _discover(tmp_path)

    assert {"gh-work", "gh-personal"} <= set(got), (
        f"a server pointed at different credentials must not be deduped away: {sorted(got)}")


def test_the_very_same_server_in_two_clients_is_still_one(tmp_path):
    """The other half — dedup must keep working, or every multi-client user gets duplicate rows."""
    spec = {"command": "npx", "args": ["-y", "server-fs"]}
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"fs": dict(spec)}})
    _write(tmp_path, ".codeium/windsurf/mcp_config.json", {"mcpServers": {"fs": dict(spec)}})

    got = _discover(tmp_path)

    assert len([k for k in got if got[k].get("command") == "npx"]) == 1, sorted(got)


def test_flattens_claude_code_per_project_nesting(tmp_path):
    # ~/.claude.json has servers under projects.<path>.mcpServers, NOT a top-level mcpServers.
    _write(tmp_path, ".claude.json", {
        "projects": {
            "/work/a": {"mcpServers": {"vault": {"command": "vault-mcp"}}},
            "/work/b": {"mcpServers": {"github": {"command": "gh-mcp"}}},
        }
    })
    got = _discover(tmp_path)
    assert set(got) == {"vault", "github"}


def test_finds_vscode_settings_and_mcp_json_shapes(tmp_path):
    _write(tmp_path, "Library/Application Support/Code/User/settings.json",
           {"mcp": {"servers": {"a": {"command": "a-mcp"}}}})
    _write(tmp_path, "Library/Application Support/Code/User/mcp.json",
           {"servers": {"b": {"command": "b-mcp"}}})
    got = _discover(tmp_path)
    assert {"a", "b"} <= set(got)


def test_tolerant_parse_keeps_https_url_intact(tmp_path):
    # A // comment AND an https:// url: naive comment-stripping would eat the url. It must survive.
    raw = """{
      // my notion server
      "mcpServers": {
        "notion": { "url": "https://mcp.notion.com/mcp", "type": "http" },
      }
    }"""
    _write(tmp_path, ".cursor/mcp.json", raw)
    got = _discover(tmp_path)
    assert got["notion"]["url"] == "https://mcp.notion.com/mcp"


def test_dedupes_same_server_across_clients(tmp_path):
    server = {"command": "npx", "args": ["-y", "server-fs"]}
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"fs": server}})
    _write(tmp_path, "Library/Application Support/Claude/claude_desktop_config.json",
           {"mcpServers": {"filesystem": server}})  # same launch identity, different name
    got = _discover(tmp_path)
    # One physical server → one entry (first sighting's name wins).
    assert len([e for e in got.values() if e.get("command") == "npx"]) == 1


def test_two_accounts_on_one_hosted_url_are_two_servers(tmp_path):
    """Same URL, different bearer token = a different account's data. Deduped on the URL alone, the
    second was never scanned, never baselined and therefore never guarded — while the fleet list
    implied it was covered. The stdio/`env` half of this was fixed earlier; `headers` is the shape
    hosted servers actually use."""
    url = "https://api.githubcopilot.com/mcp/"
    _write(tmp_path, ".cursor/mcp.json",
           {"mcpServers": {"gh-work": {"url": url, "headers": {"Authorization": "Bearer work"}}}})
    _write(tmp_path, ".codeium/windsurf/mcp_config.json",
           {"mcpServers": {"gh-personal": {"url": url, "headers": {"Authorization": "Bearer personal"}}}})
    got = _discover(tmp_path)
    assert len(got) == 2, f"two accounts collapsed into one row: {got}"


def test_the_same_hosted_account_in_two_clients_is_still_one_server(tmp_path):
    """The other direction, so the split above is not just 'never dedup a remote entry'."""
    entry = {"url": "https://mcp.notion.com/mcp", "headers": {"Authorization": "Bearer same"}}
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"notion": entry}})
    _write(tmp_path, ".codeium/windsurf/mcp_config.json", {"mcpServers": {"notion-too": entry}})
    assert len(_discover(tmp_path)) == 1


def test_disambiguates_different_servers_with_the_same_name(tmp_path):
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"db": {"command": "postgres-mcp"}}})
    _write(tmp_path, ".codeium/windsurf/mcp_config.json", {"mcpServers": {"db": {"command": "mysql-mcp"}}})
    got = _discover(tmp_path)
    assert len(got) == 2  # both kept, one renamed db#2
    assert {e["command"] for e in got.values()} == {"postgres-mcp", "mysql-mcp"}


def test_malformed_config_is_skipped_not_fatal(tmp_path):
    _write(tmp_path, ".cursor/mcp.json", "{ this is not json at all ")
    _write(tmp_path, ".codeium/windsurf/mcp_config.json", {"mcpServers": {"ok": {"command": "ok-mcp"}}})
    got = _discover(tmp_path)
    assert set(got) == {"ok"}  # the good one still found; the bad one didn't crash the run


def test_entry_without_command_or_url_is_skipped(tmp_path):
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"broken": {"note": "no command or url"}}})
    assert _discover(tmp_path) == {}


def test_nothing_configured_returns_empty(tmp_path):
    assert discover_servers(home=tmp_path, platform="darwin") == {}


def test_per_os_paths_are_selected(tmp_path):
    # The Linux Claude Desktop path is not registered; a mac-only file must NOT be found on linux.
    _write(tmp_path, "Library/Application Support/Claude/claude_desktop_config.json",
           {"mcpServers": {"mac": {"command": "mac-mcp"}}})
    assert "mac" in discover_servers(home=tmp_path, platform="darwin")
    assert discover_servers(home=tmp_path, platform="linux") == {}


def test_claude_code_user_scope_servers_are_found(tmp_path):
    """REGRESSION (found live): ~/.claude.json holds servers in TWO places — top-level `mcpServers`
    (what `claude mcp add -s user` writes) AND `projects.<path>.mcpServers`. Reading only the
    per-project half silently hid every user-scope server; on the author's machine that was
    `browserstack`, absent from every scan while the fleet view looked complete."""
    (tmp_path / ".claude.json").write_text(json.dumps({
        "mcpServers": {"user-scope": {"command": "npx", "args": ["-y", "u"]}},
        "projects": {"/some/proj": {"mcpServers": {"proj-scope": {"command": "npx", "args": ["-y", "p"]}}}},
    }), encoding="utf-8")

    found = discover_servers(home=tmp_path, platform="darwin")

    assert any("user-scope" in k for k in found), f"user-scope server missed (found {sorted(found)})"
    assert any("proj-scope" in k for k in found), "per-project server regressed"


def test_codex_toml_servers_are_found(tmp_path):
    """Codex is the one client that keeps its config in TOML. Its servers were invisible purely
    because discovery assumed every client speaks JSON — on the author's machine that hid figma."""
    cfg = tmp_path / ".codex" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text('model = "gpt-5"\n\n[mcp_servers.figma]\nurl = "https://figma.example/mcp"\n\n'
                   '[mcp_servers.local]\ncommand = "npx"\nargs = ["-y", "thing"]\n\n'
                   '[projects."/some/path"]\ntrust_level = "trusted"\n', encoding="utf-8")

    found = discover_servers(home=tmp_path, platform="darwin")

    assert any("figma" in k for k in found) and any("local" in k for k in found)
    # `[projects."..."]` is not a server table — reading the whole TOML would invent entries.
    assert not any("some/path" in k or "trust" in k for k in found)


def test_claude_desktop_extensions_are_found(tmp_path):
    """Extensions are a separate install channel — they are NEVER written into
    claude_desktop_config.json, so reading that file alone misses every installed extension."""
    man = tmp_path / "Library/Application Support/Claude/Claude Extensions/vendor.thing/manifest.json"
    man.parent.mkdir(parents=True)
    man.write_text(json.dumps({
        "name": "Revolut X", "display_name": "Revolut X",
        "server": {"type": "node", "mcp_config": {"command": "node", "args": ["${__dirname}/i.js"]}},
    }), encoding="utf-8")

    found = discover_servers(home=tmp_path, platform="darwin")

    assert "Revolut X" in found
    # ${__dirname} is resolved by the HOST at launch — we must show what will really run, not guess.
    assert found["Revolut X"]["args"] == ["${__dirname}/i.js"]


def test_an_extension_manifest_without_a_server_is_ignored(tmp_path):
    man = tmp_path / "Library/Application Support/Claude/Claude Extensions/x/manifest.json"
    man.parent.mkdir(parents=True)
    man.write_text(json.dumps({"name": "docs only", "server": {"type": "python"}}), encoding="utf-8")
    assert discover_servers(home=tmp_path, platform="darwin") == {}


def test_servers_carry_the_clients_they_came_from(tmp_path):
    """Attribution is what lets the fleet view group by IDE — and what tells a user which config
    file to open to remove a server. Dedup must not throw it away."""
    (tmp_path / ".cursor").mkdir(parents=True)
    (tmp_path / ".cursor/mcp.json").write_text(json.dumps(
        {"mcpServers": {"shared": {"command": "npx", "args": ["-y", "s"]}}}), encoding="utf-8")
    (tmp_path / ".kiro/settings").mkdir(parents=True)
    (tmp_path / ".kiro/settings/mcp.json").write_text(json.dumps(
        {"mcpServers": {"shared": {"command": "npx", "args": ["-y", "s"]}}}), encoding="utf-8")

    found = discover_servers(home=tmp_path, platform="darwin")

    # ONE scannable entry (dedup by launch identity) that knows about BOTH tools.
    assert len(found) == 1
    assert sorted(next(iter(found.values()))["_clients"]) == ["cursor", "kiro"]


def test_attribution_never_changes_what_gets_scanned(tmp_path):
    (tmp_path / ".cursor").mkdir(parents=True)
    (tmp_path / ".cursor/mcp.json").write_text(json.dumps(
        {"mcpServers": {"a": {"command": "npx", "args": ["-y", "a"]}}}), encoding="utf-8")
    entry = next(iter(discover_servers(home=tmp_path, platform="darwin").values()))
    assert entry["command"] == "npx" and entry["args"] == ["-y", "a"]


def test_unscannable_capabilities_are_detected_from_local_traces(tmp_path):
    (tmp_path / ".claude").mkdir(parents=True)
    (tmp_path / ".claude/mcp-needs-auth-cache.json").write_text(
        json.dumps({"claude.ai Gmail": {"id": "x"}, "claude.ai Drive": {"id": "y"}}), encoding="utf-8")
    hosts = tmp_path / "Library/Application Support/Google/Chrome/NativeMessagingHosts"
    hosts.mkdir(parents=True)
    (hosts / "com.anthropic.claude_browser_extension.json").write_text("{}", encoding="utf-8")

    found = detect_unscannable(home=tmp_path, platform="darwin")

    names = [f["name"] for f in found]
    assert "claude.ai Gmail" in names and "claude.ai Drive" in names
    assert "claude-browser-extension" in names
    assert {f["kind"] for f in found} == {"account-hosted", "browser-host"}


def test_no_traces_means_no_unscannable_claims(tmp_path):
    assert detect_unscannable(home=tmp_path, platform="darwin") == []


# --- the honesty quick-wins (2026-08-01): report, BOM, entry shapes --------------------------- #
# Discovery's dangerous property was that every miss rendered identically to "you're clean":
# a BOM'd config, a PermissionError, an unrecognised entry shape and a genuinely empty machine
# all produced the same bare dict. discover_report() gives the sweep a vocabulary for partial
# failure; these tests lock each formerly-silent case to a visible outcome.

def test_bom_prefixed_config_is_parsed_not_discarded(tmp_path):
    # utf-8-sig: a BOM (common on Windows / some editors) used to fail json.loads and silently
    # drop the client's ENTIRE config.
    raw = "﻿" + json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "s"]}}})
    _write(tmp_path, ".cursor/mcp.json", raw)
    assert "fs" in _discover(tmp_path)


def test_serverurl_and_httpurl_spellings_become_scannable(tmp_path):
    # Windsurf/Cline write `serverUrl`; Gemini CLI streamable-HTTP writes `httpUrl`. Both were
    # dropped with no trace; now they normalise to the `url` key probe launches from.
    _write(tmp_path, ".codeium/windsurf/mcp_config.json",
           {"mcpServers": {"wind": {"serverUrl": "https://a.example/mcp"}}})
    _write(tmp_path, ".gemini/settings.json",
           {"mcpServers": {"gem": {"httpUrl": "https://b.example/mcp"}}})
    got = _discover(tmp_path)
    assert got["wind"]["url"] == "https://a.example/mcp"
    assert got["gem"]["url"] == "https://b.example/mcp"


def test_disabled_entries_are_skipped_and_reported_not_scanned_as_live(tmp_path):
    from mcpgawk.discover import discover_report
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {
        "on": {"command": "on-mcp"},
        "off": {"command": "off-mcp", "disabled": True}}})
    servers, sources = discover_report(home=tmp_path, platform="darwin")
    assert set(servers) == {"on"}, "the client itself will not launch a disabled server"
    cursor = next(s for s in sources if s["client"] == "cursor")
    assert cursor["disabled"] == ["off"], "skipped-but-recorded, never silently gone"


def test_report_distinguishes_absent_unparsable_and_ok(tmp_path):
    from mcpgawk.discover import ABSENT, OK, UNPARSABLE, discover_report
    _write(tmp_path, ".cursor/mcp.json", "{ not json ")
    _write(tmp_path, ".codeium/windsurf/mcp_config.json",
           {"mcpServers": {"ok": {"command": "ok-mcp"}}})
    servers, sources = discover_report(home=tmp_path, platform="darwin")
    by_client = {}
    for s in sources:
        by_client.setdefault(s["client"], []).append(s)
    assert by_client["cursor"][0]["status"] == UNPARSABLE, \
        "a config that EXISTS but won't parse must never read like an empty machine"
    wind = by_client["windsurf"][0]
    assert wind["status"] == OK and wind["servers"] == 1
    assert by_client["claude-desktop"][0]["status"] == ABSENT
    assert set(servers) == {"ok"}


def test_report_marks_unreadable_configs(tmp_path):
    import os
    import sys as _sys

    import pytest as _pytest
    # POSIX-only: Windows has no geteuid, and chmod(0o000) does not deny reads there — the
    # unreadable-config path is real on Windows (ACLs, locked files) but cannot be provoked
    # this way, so asserting it here would be a test of nothing. Found by the windows-latest
    # runner on its first ever run.
    if _sys.platform.startswith("win"):
        _pytest.skip("permission bits do not deny reads on Windows")
    if os.geteuid() == 0:
        _pytest.skip("permission bits do not bind root")
    from mcpgawk.discover import UNREADABLE, discover_report
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"fs": {"command": "npx"}}})
    (tmp_path / ".cursor/mcp.json").chmod(0o000)
    try:
        _servers, sources = discover_report(home=tmp_path, platform="darwin")
        cursor = next(s for s in sources if s["client"] == "cursor")
        assert cursor["status"] == UNREADABLE, \
            "a PermissionError is a fact to report, not an empty machine"
    finally:
        (tmp_path / ".cursor/mcp.json").chmod(0o644)


def test_report_names_unrecognised_entry_shapes(tmp_path):
    from mcpgawk.discover import discover_report
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {
        "fine": {"command": "x"},
        "mystery": {"transportKind": "quic", "endpoint": "wss://c.example"}}})
    servers, sources = discover_report(home=tmp_path, platform="darwin")
    cursor = next(s for s in sources if s["client"] == "cursor")
    assert cursor["unrecognised"] == ["mystery"]
    assert cursor["servers"] == 1 and set(servers) == {"fine"}


def test_discover_servers_wrapper_is_unchanged_by_the_report(tmp_path):
    from mcpgawk.discover import discover_report
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"fs": {"command": "npx"}}})
    servers, _sources = discover_report(home=tmp_path, platform="darwin")
    assert servers == discover_servers(home=tmp_path, platform="darwin")


# --- project-scoped configs (the Phase 3 promise from audit-discovery-scope-2026-07-19) -------- #
# A repo-committed .mcp.json is how a TEAM shares servers — the dominant pattern for shared
# config, and invisible to a $HOME-only sweep. These lock the sweep, its bounds, and its honesty.

def test_finds_servers_in_a_repo_committed_mcp_json(tmp_path):
    proj = tmp_path / "work" / "acme"
    proj.mkdir(parents=True)
    (proj / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"team-db": {"command": "team-db-mcp"}}}), encoding="utf-8")
    got = discover_servers(home=tmp_path, platform="darwin", cwd=proj)
    assert "team-db" in got, "a server the whole team loads must not be invisible"


def test_project_configs_are_found_via_claude_codes_project_map(tmp_path):
    proj = tmp_path / "repos" / "beta"
    (proj / ".cursor").mkdir(parents=True)
    (proj / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"beta-srv": {"command": "beta-mcp"}}}), encoding="utf-8")
    _write(tmp_path, ".claude.json", {"projects": {str(proj): {"mcpServers": {}}}})
    got = discover_servers(home=tmp_path, platform="darwin", cwd=tmp_path)
    assert "beta-srv" in got, "projects the machine's agents know about are swept too"


def test_a_project_server_also_configured_at_home_is_not_scanned_twice(tmp_path):
    server = {"command": "npx", "args": ["-y", "shared"]}
    proj = tmp_path / "w"
    proj.mkdir()
    (proj / ".mcp.json").write_text(json.dumps({"mcpServers": {"shared": server}}),
                                    encoding="utf-8")
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"shared-home": server}})
    got = discover_servers(home=tmp_path, platform="darwin", cwd=proj)
    assert len([e for e in got.values() if e.get("command") == "npx"]) == 1


def test_project_rows_appear_in_the_report_with_their_real_path(tmp_path):
    from mcpgawk.discover import OK, discover_report
    proj = tmp_path / "w"
    proj.mkdir()
    (proj / ".mcp.json").write_text(json.dumps({"mcpServers": {"p": {"command": "x"}}}),
                                    encoding="utf-8")
    _servers, sources = discover_report(home=tmp_path, platform="darwin", cwd=proj)
    # By ABSOLUTE path: a substring match on ".mcp.json" would also catch Warp's ~/.warp/.mcp.json.
    proj_rows = [s for s in sources if s["path"] == str(proj / ".mcp.json")]
    assert len(proj_rows) == 1
    assert proj_rows[0]["status"] == OK and proj_rows[0]["servers"] == 1
    assert str(proj) in proj_rows[0]["path"], "the row names WHICH project it read"


def test_absent_project_files_do_not_flood_the_report(tmp_path):
    from mcpgawk.discover import discover_report
    projects = {}
    for i in range(5):
        p = tmp_path / f"proj{i}"
        p.mkdir()
        projects[str(p)] = {"mcpServers": {}}
    _write(tmp_path, ".claude.json", {"projects": projects})
    _servers, sources = discover_report(home=tmp_path, platform="darwin", cwd=tmp_path)
    assert not [s for s in sources if "proj" in s["path"]], \
        "3 empty rows per project ever opened would drown the real report"


def test_the_project_sweep_is_bounded(tmp_path):
    from mcpgawk import discover as disc
    projects = {}
    for i in range(disc._MAX_PROJECTS + 15):
        p = tmp_path / f"p{i}"
        p.mkdir()
        projects[str(p)] = {"mcpServers": {}}
    _write(tmp_path, ".claude.json", {"projects": projects})
    dirs = disc.project_dirs(tmp_path, cwd=None)
    assert len(dirs) <= disc._MAX_PROJECTS, "discovery runs on every scan; it must stay fast"


def test_a_broken_project_config_is_reported_like_any_other_source(tmp_path):
    from mcpgawk.discover import UNPARSABLE, discover_report
    proj = tmp_path / "w"
    proj.mkdir()
    (proj / ".mcp.json").write_text("{ nope", encoding="utf-8")
    _servers, sources = discover_report(home=tmp_path, platform="darwin", cwd=proj)
    rows = [s for s in sources if s["path"] == str(proj / ".mcp.json")]
    assert rows and rows[0]["status"] == UNPARSABLE


def test_home_is_never_swept_as_a_project(tmp_path):
    """$HOME is in Claude Code's own project map on a real machine (found by running this against
    the author's machine, not by a fixture). Sweeping it as a project re-reads ~/.cursor/mcp.json
    under an absolute path — one source counted twice, which reads as two sources agreeing."""
    from mcpgawk.discover import discover_report, project_dirs
    _write(tmp_path, ".cursor/mcp.json", {"mcpServers": {"home-srv": {"command": "x"}}})
    _write(tmp_path, ".claude.json", {"projects": {str(tmp_path): {"mcpServers": {}}}})
    assert tmp_path.resolve() not in project_dirs(tmp_path, cwd=tmp_path)
    _servers, sources = discover_report(home=tmp_path, platform="darwin", cwd=tmp_path)
    cursor_rows = [s for s in sources if s["path"].endswith(".cursor/mcp.json")]
    assert len(cursor_rows) == 1, f"one file, one row — got {[r['path'] for r in cursor_rows]}"


# --- the 2026-08-02 client tier ---------------------------------------------------------------- #
# Each path here was checked against official docs or the project's own source; the two clients
# that could NOT be verified (Trae, JetBrains AI Assistant) are named in UNVERIFIED_CLIENTS
# instead of being guessed at. These tests cover the VOCABULARY differences, which is where a
# new client silently contributes nothing: Goose says `cmd`, opencode packs argv into one list,
# Continue's servers are a LIST, Amp's key is literally dotted, Zed says `context_servers`.

def test_zed_context_servers_are_mcp_servers(tmp_path):
    _write(tmp_path, ".config/zed/settings.json",
           {"context_servers": {"zsrv": {"command": "zed-mcp", "args": ["--x"]}}})
    got = _discover(tmp_path)
    assert got["zsrv"]["command"] == "zed-mcp"


def test_opencode_packs_argv_into_one_list(tmp_path):
    _write(tmp_path, ".config/opencode/opencode.json",
           {"mcp": {"oc": {"type": "local", "command": ["npx", "-y", "oc-mcp"]}},
            "model": "anthropic/claude"})
    got = _discover(tmp_path)
    assert got["oc"]["command"] == "npx" and got["oc"]["args"] == ["-y", "oc-mcp"]


def test_opencode_remote_entry_is_a_url(tmp_path):
    _write(tmp_path, ".config/opencode/opencode.json",
           {"mcp": {"ocr": {"type": "remote", "url": "https://h/mcp"}}})
    assert _discover(tmp_path)["ocr"]["url"] == "https://h/mcp"


def test_amps_dotted_key_is_the_key(tmp_path):
    _write(tmp_path, ".config/amp/settings.json",
           {"amp.mcpServers": {"amps": {"command": "amp-mcp"}}, "amp.theme": "dark"})
    assert "amps" in _discover(tmp_path)


def test_goose_says_cmd_not_command(tmp_path):
    _write(tmp_path, ".config/goose/config.yaml",
           "extensions:\n  gs:\n    type: stdio\n    cmd: goose-mcp\n    args: ['--go']\n")
    got = _discover(tmp_path)
    assert got["gs"]["command"] == "goose-mcp", "Goose's own vocabulary must be normalised"


def test_goose_remote_uses_uri(tmp_path):
    _write(tmp_path, ".config/goose/config.yaml",
           "extensions:\n  gr:\n    type: streamable_http\n    uri: https://h/mcp\n")
    assert _discover(tmp_path)["gr"]["url"] == "https://h/mcp"


def test_goose_list_form_is_accepted_too(tmp_path):
    """The docs show a list; real files are commonly a map. Picking one would silently lose the
    other operator's servers."""
    _write(tmp_path, ".config/goose/config.yaml",
           "extensions:\n  - name: gl\n    type: stdio\n    cmd: gl-mcp\n")
    assert "gl" in _discover(tmp_path)


def test_continue_servers_are_a_list_that_names_itself(tmp_path):
    _write(tmp_path, ".continue/config.yaml",
           "mcpServers:\n  - name: cont\n    command: cont-mcp\n    args: ['-y']\n")
    got = _discover(tmp_path)
    assert got["cont"]["command"] == "cont-mcp", "the only list-shaped declaration we read"


def test_cline_and_roo_live_in_vscode_global_storage(tmp_path):
    _write(tmp_path, "Library/Application Support/Code/User/globalStorage/"
                     "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
           {"mcpServers": {"cl": {"command": "cl-mcp"}}})
    _write(tmp_path, "Library/Application Support/Code/User/globalStorage/"
                     "rooveterinaryinc.roo-cline/settings/mcp_settings.json",
           {"mcpServers": {"ro": {"command": "ro-mcp"}}})
    got = _discover(tmp_path)
    assert {"cl", "ro"} <= set(got)


def test_warp_uses_a_dot_prefixed_filename(tmp_path):
    _write(tmp_path, ".warp/.mcp.json", {"mcpServers": {"wp": {"command": "wp-mcp"}}})
    assert "wp" in _discover(tmp_path)


def test_lmstudio_is_read_from_both_its_documented_and_actual_paths(tmp_path):
    _write(tmp_path, ".cache/lm-studio/mcp.json", {"mcpServers": {"lm": {"command": "lm-mcp"}}})
    assert "lm" in _discover(tmp_path), \
        "an open bug report says macOS writes here, not to the documented ~/.lmstudio"


def test_linux_claude_desktop_is_now_read(tmp_path):
    """Anthropic ships an official Linux build but documents no config path. Reading the
    community-corroborated one costs an `absent` row if wrong and finds real servers if right —
    previously a Linux user got nothing from this client at all."""
    _write(tmp_path, ".config/Claude/claude_desktop_config.json",
           {"mcpServers": {"cd": {"command": "cd-mcp"}}})
    assert "cd" in discover_servers(home=tmp_path, platform="linux")


def test_project_scopes_for_the_new_tier(tmp_path):
    proj = tmp_path / "repo"
    (proj / ".roo").mkdir(parents=True)
    (proj / ".roo" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"roo-p": {"command": "roo-mcp"}}}), encoding="utf-8")
    (proj / "opencode.json").write_text(
        json.dumps({"mcp": {"oc-p": {"type": "local", "command": ["oc-mcp"]}}}), encoding="utf-8")
    got = discover_servers(home=tmp_path, platform="darwin", cwd=proj)
    assert {"roo-p", "oc-p"} <= set(got)


def test_a_yaml_config_without_pyyaml_is_reported_not_silently_dropped(tmp_path, monkeypatch):
    """The Codex/tomli rule, applied to YAML: a missing parser is a REPORTED gap. Silence would
    make Goose and Continue users look like they have no servers."""
    from mcpgawk import discover as disc
    _write(tmp_path, ".config/goose/config.yaml", "extensions:\n  gs:\n    cmd: gs-mcp\n")
    monkeypatch.setattr(disc, "_yaml_available", lambda: False)
    servers, sources = disc.discover_report(home=tmp_path, platform="darwin", cwd=tmp_path)
    assert "gs" not in servers
    row = next(s for s in sources if s["path"] == ".config/goose/config.yaml")
    assert row["status"] == disc.NO_PARSER
    assert any("PyYAML is not installed" in ln for ln in disc.problem_lines(sources))


def test_unverified_clients_are_recorded_not_guessed_at():
    """Trae's paths conflict between community sources and JetBrains AI Assistant stores servers
    in IDE options with no file. Shipping a guessed path would let us CLAIM support while finding
    nothing — the exact failure this module exists to avoid."""
    from mcpgawk.discover import SUPPORTED_CLIENTS, UNVERIFIED_CLIENTS
    assert "trae" in UNVERIFIED_CLIENTS and "jetbrains-ai-assistant" in UNVERIFIED_CLIENTS
    assert not (set(UNVERIFIED_CLIENTS) & set(SUPPORTED_CLIENTS)), \
        "a client cannot be both unverified and supported"


def test_every_supported_client_has_a_display_label():
    """A client added to the registry without a label renders as a raw id on every surface
    (antigravity and claude-desktop-extension did exactly that until 2026-08-01)."""
    from mcpgawk.discover import SUPPORTED_CLIENTS
    from mcpgawk.status import CLIENT_LABELS
    missing = [c for c in SUPPORTED_CLIENTS if c not in CLIENT_LABELS]
    assert not missing, f"no display label for: {missing}"


# --- the auth-required record (2026-08-02) ------------------------------------------------------ #

def test_auth_needed_record_round_trips_and_is_rewritten_wholesale(tmp_path):
    """A failed probe never reaches history, so the fact that a server answered 401/403 used to
    die with the scan — leaving a UI unable to say "this needs your sign-in" for any server that
    was not an mcp-remote launcher. Rewritten wholesale each scan so an offer never outlives the
    problem it was made about."""
    from mcpgawk import remote_login
    store = tmp_path / "auth-needed.json"
    remote_login.record_auth_needed({"api": "https://api.example.com/mcp"}, path=store)
    assert remote_login.auth_needed(path=store) == {"api": "https://api.example.com/mcp"}
    remote_login.record_auth_needed({}, path=store)
    assert remote_login.auth_needed(path=store) == {}, \
        "a server that no longer refuses us must stop being listed"
    assert remote_login.auth_needed(path=tmp_path / "nope.json") == {}


def test_login_url_resolves_both_shapes(tmp_path):
    from mcpgawk import remote_login
    store = tmp_path / "auth-needed.json"
    wrapped = {"command": "npx", "args": ["mcp-remote", "https://w.example.com/mcp"]}
    remote = {"url": "https://r.example.com/mcp"}
    assert remote_login.login_url(wrapped, "kite", path=store) == "https://w.example.com/mcp"
    assert remote_login.login_url(remote, "api", path=store) == "", "no evidence, no offer"
    remote_login.record_auth_needed({"api": "https://r.example.com/mcp"}, path=store)
    assert remote_login.login_url(remote, "api", path=store) == "https://r.example.com/mcp"
