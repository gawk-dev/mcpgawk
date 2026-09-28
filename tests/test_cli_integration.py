"""cli.main() integration: entry-threading for the opt-in checks (--supply-chain/--oauth-scopes
need the raw launch command/headers the core scan discards), with everything network/subprocess
mocked so this runs offline and fast."""
from __future__ import annotations

import json

import pytest

from mcpgawk import cli
from mcpgawk.probe import ServerSnapshot
from mcpgawk.supplychain import SupplyChainFinding


@pytest.fixture(autouse=True)
def _isolated_history(monkeypatch, tmp_path):
    """scan persists baselines to ~/.mcpgawk/history.json (the ONLY state mcpgawk keeps) and the
    exit code counts drift/re-identification against them. Unisolated, these tests collide with
    the REAL history on a developer machine — the fake 'request'/'example.com' snapshots read as
    a rug-pull against genuine baselines and rc flips to 1. That is a correct exit code fed by
    leaked state: these two failed for WEEKS on the founder's machine while passing on fresh CI."""
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))


def _fake_snapshot(name, transport):
    return ServerSnapshot(name=name, transport=transport, protocol_version="2025-11-25",
                          tools=[{"name": "a", "description": "read a thing"}])


async def _fake_probe_stdio(name, command, args=None, env=None, timeout=90.0):
    return _fake_snapshot(name, "stdio")


async def _fake_probe_url(name, url, headers=None, timeout=90.0, auth=None,
                          declared="http", permute=True):
    # The CLI's remote seam is now the permuting prober (transport permutation), not probe_http.
    return _fake_snapshot(name, "http")


def test_only_with_no_match_exits_2_instead_of_crashing(tmp_path, capsys):
    """A typo at `--only` is a normal outcome, not a traceback.

    The no-match branch returned a bare int from `_run`, whose caller unpacks a 3-tuple — so every
    `--only` typo raised `TypeError: cannot unpack non-iterable int object`, printed a traceback on
    top of the friendly message, and was filed in the run log as a tool ERROR. Four independent
    review angles reproduced it; no test drove an unmatched `--only` at all.

    This drives `cli.main` — the real entry point — because the defect lived in the seam between
    `_run` and its caller, which a unit test of either half would have missed.
    """
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"alpha": {"command": "true", "args": []}}}))

    code = cli.main(["scan", str(cfg), "--only", "nosuchserver", "--yes"])

    assert code == 2, f"expected exit 2 for an unmatched --only, got {code!r}"
    err = capsys.readouterr().err
    assert "no server matches --only nosuchserver" in err
    assert "alpha" in err, "the message must name what IS configured, so a typo is obvious"
    assert "Traceback" not in err


def test_supply_chain_flag_reaches_the_launch_command(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_stdio", _fake_probe_stdio)
    seen = {}
    def fake_check(command, args):
        seen["command"], seen["args"] = command, args
        return SupplyChainFinding("npm", "request", "2.88.2", deprecated=True,
                                  detail="request has been deprecated")
    monkeypatch.setattr(cli, "check_supply_chain", fake_check)

    rc = cli.main(["scan", "--stdio", "npx -y request", "--supply-chain"])

    assert seen["command"] == "npx" and seen["args"] == ["-y", "request"]
    out = capsys.readouterr().out
    assert "DEPRECATED/YANKED" in out
    assert rc == 0


def test_supply_chain_missing_package_prints_even_when_the_launch_fails(monkeypatch, capsys):
    """`npx -y <a name that does not exist>` fails to launch — the scan's failure branch must still
    print the registry's answer, because it is the only line that says WHY."""
    async def failing_probe(name, command, args=None, env=None, timeout=90.0):
        return ServerSnapshot(name=name, transport="stdio", protocol_version=None, tools=[],
                              error="npm error 404 Not Found - GET https://registry.npmjs.org/"
                                    "some-postgres-mcp", error_kind="server-failed")
    monkeypatch.setattr(cli, "probe_stdio", failing_probe)
    monkeypatch.setattr(cli, "check_supply_chain", lambda command, args: SupplyChainFinding(
        "npm", "some-postgres-mcp", None, deprecated=False, missing=True))

    cli.main(["scan", "--stdio", "npx -y some-postgres-mcp", "--supply-chain"])

    out = capsys.readouterr().out
    assert "hallucinated or not yet registered" in out and "Do not launch it" in out


def test_oauth_scopes_flag_reaches_supplied_headers(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_url", _fake_probe_url)

    rc = cli.main(["scan", "--http", "https://example.com/mcp",
                   "--header", "Authorization: Bearer not-a-jwt", "--oauth-scopes"])

    out = capsys.readouterr().out
    assert "not locally inspectable" in out  # opaque token, honestly reported
    assert rc == 0


def test_opt_in_flags_absent_by_default(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_stdio", _fake_probe_stdio)
    cli.main(["scan", "--stdio", "npx -y request"])
    out = capsys.readouterr().out
    assert "supply-chain" not in out
    assert "oauth scopes" not in out


def test_json_output_carries_opt_in_fields_only_when_requested(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_stdio", _fake_probe_stdio)
    cli.main(["scan", "--stdio", "npx -y request", "--json"])
    labels = json.loads(capsys.readouterr().out)
    assert "supply_chain" not in labels[0]["x-mcpgawk"]


# --- the registry check GATES the launch (--supply-chain on the consent path) -------------------

def _two_server_config(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "ghost": {"command": "npx", "args": ["-y", "ghost-postgres-mcp"]},
        "real": {"command": "npx", "args": ["-y", "real-pkg"]}}}))
    return cfg


@pytest.fixture
def _gate(monkeypatch, tmp_path):
    """Redirect every store, stub the launcher and the registry. `launched` records every server
    probe() was asked to start; `checked` every registry lookup."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GAWK_OAUTH_KEY_BACKEND", "file")
    launched, checked = [], []

    async def fake_probe(entry, name):
        launched.append(name)
        return _fake_snapshot(name, "stdio")
    monkeypatch.setattr(cli, "probe", fake_probe)

    answers = {"ghost-postgres-mcp": dict(missing=True),
               "real-pkg": dict(version="1.0.0", young=True, first_published="2026-09-20",
                                age_days=8, release_count=1),
               "down-pkg": dict(error="URLError: timed out")}

    def fake_check(command, args):
        pkg = args[-1]
        checked.append(pkg)
        a = dict(answers[pkg])
        return SupplyChainFinding("npm", pkg, a.pop("version", None), deprecated=False, **a)
    monkeypatch.setattr(cli, "check_supply_chain", fake_check)
    return launched, checked


def test_a_package_the_registry_does_not_have_is_never_launched(_gate, tmp_path, capsys):
    launched, checked = _gate
    rc = cli.main(["scan", str(_two_server_config(tmp_path)), "--yes", "--supply-chain", "--detail"])
    out = capsys.readouterr().out
    assert launched == ["real"], "the missing package must not be launched; the young one still is"
    assert sorted(checked) == ["ghost-postgres-mcp", "real-pkg"], "one registry call per server"
    assert ("✗ NOT ON NPM — hallucinated or not yet registered; nothing to trust yet. "
            "Do not launch it.") in out
    assert "NOT LAUNCHED" in out and "could not scan" not in out
    assert "young name" in out
    assert rc != 0


def test_a_missing_package_reads_not_launched_in_json_and_fleet(_gate, tmp_path, capsys):
    cfg = _two_server_config(tmp_path)
    cli.main(["scan", str(cfg), "--yes", "--supply-chain", "--json"])
    labels = {lab["name"]: lab for lab in json.loads(capsys.readouterr().out)}
    x = labels["ghost"]["x-mcpgawk"]
    assert x["is_failure"] and x["error_kind"] == "not-launched"
    assert x["supply_chain"]["missing"] is True
    assert x["narrative"]["state"] == "not-launched", "never 'unreachable' — nothing was tried"
    cli.main(["scan", str(cfg), "--yes", "--supply-chain", "--fleet-json"])
    rows = {r["name"]: r for r in json.loads(capsys.readouterr().out)["servers"]}
    assert rows["ghost"]["state"] == "SKIPPED"
    assert "not launched" in rows["ghost"]["detail"] and "not on npm" in rows["ghost"]["detail"]
    assert "--yes" not in rows["ghost"]["detail"]


def test_a_missing_package_is_reported_even_when_consent_is_withheld(_gate, tmp_path, capsys,
                                                                     monkeypatch):
    launched, _ = _gate
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    cli.main(["scan", str(_two_server_config(tmp_path)), "--supply-chain", "--detail"])
    cap = capsys.readouterr()
    assert launched == []
    assert "NOT ON NPM" in cap.out
    assert "ghost" not in cap.err.split("would be LAUNCHED", 1)[-1], \
        "a name that does not exist is never offered for launch"


def test_the_fleet_view_does_not_tell_you_to_rerun_a_missing_package_with_yes(_gate, tmp_path,
                                                                             capsys):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "ghost": {"command": "npx", "args": ["-y", "ghost-postgres-mcp"]},
        "web": {"url": "https://example.com/mcp"}}}))
    cli.main(["scan", str(cfg), "--yes", "--supply-chain"])
    out = capsys.readouterr().out
    assert "not launched" in out and "Re-run with --yes" not in out


def test_could_not_check_still_launches_and_says_not_checked_is_not_clean(_gate, tmp_path, capsys):
    launched, checked = _gate
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"down": {"command": "npx", "args": ["-y", "down-pkg"]}}}))
    cli.main(["scan", str(cfg), "--yes", "--supply-chain"])
    assert launched == ["down"] and checked == ["down-pkg"]
    assert "Not checked is not clean." in capsys.readouterr().out


def test_without_supply_chain_nothing_is_checked_and_everything_launches(_gate, tmp_path, capsys):
    launched, checked = _gate
    cli.main(["scan", str(_two_server_config(tmp_path)), "--yes"])
    assert sorted(launched) == ["ghost", "real"] and checked == []


# --- `scan --stdio "npx -y <name>" --supply-chain`: the same gate as the config path -----------
# The empty-fleet message recommends exactly this command to "check a server before you add it",
# and it LAUNCHED before asking the registry — so a hallucinated name ran whatever squatted it.

def _stdio_gate(monkeypatch, tmp_path, answer):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GAWK_OAUTH_KEY_BACKEND", "file")
    launched, checked = [], []

    async def fake_probe_stdio(name, command, args=None, env=None, timeout=90.0):
        launched.append(args[-1])
        return _fake_snapshot(name, "stdio")
    monkeypatch.setattr(cli, "probe_stdio", fake_probe_stdio)

    def fake_check(command, args):
        checked.append(args[-1])
        a = dict(answer)
        return SupplyChainFinding("npm", args[-1], a.pop("version", None), deprecated=False, **a)
    monkeypatch.setattr(cli, "check_supply_chain", fake_check)
    return launched, checked


def test_stdio_a_package_the_registry_does_not_have_is_never_launched(monkeypatch, tmp_path,
                                                                       capsys):
    launched, checked = _stdio_gate(monkeypatch, tmp_path, dict(missing=True))
    rc = cli.main(["scan", "--stdio", "npx -y ghost-x", "--supply-chain"])
    out = capsys.readouterr().out
    assert launched == [], "a name the registry does not have must never be launched"
    assert checked == ["ghost-x"], "one registry call per server"
    assert "NOT LAUNCHED — PACKAGE DOES NOT EXIST" in out
    assert "NOT ON NPM" in out and "could not scan" not in out
    assert rc != 0


def test_stdio_a_missing_package_reads_not_launched_in_json(monkeypatch, tmp_path, capsys):
    _stdio_gate(monkeypatch, tmp_path, dict(missing=True))
    cli.main(["scan", "--stdio", "npx -y ghost-x", "--supply-chain", "--json"])
    x = json.loads(capsys.readouterr().out)[0]["x-mcpgawk"]
    assert x["error_kind"] == "not-launched" and x["supply_chain"]["missing"] is True
    assert x["narrative"]["state"] == "not-launched"


@pytest.mark.parametrize("answer,expect", [
    (dict(error="URLError: timed out"), "Not checked is not clean."),
    (dict(version="1.0.0", young=True, first_published="2026-09-20", age_days=8,
          release_count=1), "young name"),
])
def test_stdio_could_not_check_and_young_still_launch_with_one_registry_call(
        monkeypatch, tmp_path, capsys, answer, expect):
    launched, checked = _stdio_gate(monkeypatch, tmp_path, answer)
    cli.main(["scan", "--stdio", "npx -y some-pkg", "--supply-chain"])
    assert launched == ["some-pkg"]
    assert checked == ["some-pkg"], "the pre-launch answer is reused by the label, not re-asked"
    assert expect in capsys.readouterr().out


# --- the ambient line counts only servers that actually ran -------------------------------------

def _capture_local_servers(monkeypatch):
    seen = []
    real = cli.render_summary

    def spy(labels, local_servers=0):
        seen.append(local_servers)
        return real(labels, local_servers=local_servers)
    monkeypatch.setattr(cli, "render_summary", spy)
    return seen


def test_ambient_count_excludes_a_server_refused_by_the_registry(_gate, tmp_path, capsys,
                                                                 monkeypatch):
    seen = _capture_local_servers(monkeypatch)
    cli.main(["scan", str(_two_server_config(tmp_path)), "--yes", "--supply-chain", "--detail"])
    assert seen == [1], "only `real` ran; `ghost` was never launched"


def test_ambient_count_keeps_a_declined_server_but_not_a_missing_one(_gate, tmp_path, capsys,
                                                                     monkeypatch):
    """A server declined HERE still runs in your IDE with your credentials (4dd441f), so it counts;
    a package the registry does not have can run nowhere, so it does not."""
    seen = _capture_local_servers(monkeypatch)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    cli.main(["scan", str(_two_server_config(tmp_path)), "--detail", "--supply-chain"])
    assert seen and seen[-1] == 1, seen                 # "real" (declined) counts; "ghost" (missing) does not


def test_ambient_count_excludes_a_missing_stdio_package(monkeypatch, tmp_path, capsys):
    _stdio_gate(monkeypatch, tmp_path, dict(missing=True))
    seen = _capture_local_servers(monkeypatch)
    cli.main(["scan", "--stdio", "npx -y ghost-x", "--supply-chain"])
    assert seen == [0]


def test_supply_chain_help_discloses_the_pre_consent_lookup(capsys):
    with pytest.raises(SystemExit):
        cli.main(["scan", "--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "before anything launches" in help_text
    assert "including servers you then decline" in help_text


def test_no_turn_checking_on_advice_when_the_only_server_does_not_exist(monkeypatch, tmp_path, capsys):
    _stdio_gate(monkeypatch, tmp_path, dict(missing=True))
    cli.main(["scan", "--stdio", "npx -y ghost-x", "--supply-chain"])
    out = capsys.readouterr().out
    assert "NOT LAUNCHED" in out
    assert "Your agents are not checking these servers yet" not in out
