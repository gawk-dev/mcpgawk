"""Config-only findings (configcheck.py) — the beta-tester-1 fix.

Her non-interactive first scan declined every local server and the product said "Findings 0" —
because nothing was scanned, not because nothing was wrong. This file pins the whole path:

1. UNIT, both directions per detector — every firing fixture has a clean twin, so deleting or
   inverting a detector goes red here (mutation-proofing built into the corpus, same discipline
   as test_signals.py's CLEAN/POISON split).
2. REGISTRY canary — every emitted kind is registered, every registered kind fires here, every
   kind has a render lead and a one-line SHORT name (the anti-drift shape of test_canary_signals).
3. EVIDENCE is value-free — a finding that prints the credential ships it into every checkup
   bundle; asserted on every poison fixture, not sampled.
4. THE ACCEPTANCE TEST the design entry pre-registered: a fixture config carrying all four
   issues, every launch declined, then assert what `scan` PRINTS and what the PANEL RENDERS both
   carry the findings — the rendered output, not the helpers.
"""
from __future__ import annotations

import json
import sys

import pytest

from mcpgawk import cli, fleet, panel
from mcpgawk.configcheck import CONFIG_KINDS, RISKY_KINDS, SHORT, check
from mcpgawk.label import _SIGNAL_LEAD, _SIGNAL_LEAD_BY_KIND


def _claude_desktop_config(home):
    """Where THIS platform's Claude Desktop config lives, taken from the product's own table.

    Hardcoding the macOS path (`Library/Application Support/Claude`) made three of these tests
    assert nothing on Linux: discovery reads `.config/Claude` there, found no servers, and the
    panel they inspect rendered empty. Green on the author's Mac, red in the public repo's Linux
    CI — the run that gates `twine upload`. Asking `discover._locations` keeps the test on the
    same single source of truth as the code, so a path change cannot silently un-test this.
    """
    from mcpgawk import discover as _discover
    rel = next(p for client, p, _shape in _discover._locations(sys.platform)
               if client == "claude-desktop")
    path = home / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


# One secret-shaped value per place a credential can hide. Split so no literal is push-protection
# bait; NEVER printed by the product — test 3 asserts exactly that.
GHP = "ghp_" + "abcdefghij0123456789abcdefghij012345"
OPAQUE = "q7Xr" + "TpL2mN8vK4wZs6Yb1Ce3"          # 24 chars, name-based assignment shape
BEARER = "sk-" + "abc123def456ghi789jkl012mno345pqr678"


def _entry(**over):
    base = {"command": "npx", "args": ["-y", "example-pkg@1.2.3"], "env": {}}
    base.update(over)
    return base


# --- 1. UNIT: each detector, both directions ----------------------------------------------------

@pytest.mark.parametrize("args", [["-y", "example-pkg"], ["-y", "example-pkg@latest"]])
def test_unpinned_npm_fires(args):
    kinds = [f.kind for f in check("s", _entry(args=args))]
    assert kinds == ["config:unpinned-package"]


@pytest.mark.parametrize("entry", [
    _entry(),                                                      # pinned npm
    _entry(command="uvx", args=["example-pkg==1.0.0"]),           # pinned pypi (PEP 508)
    _entry(command="uvx", args=["example-pkg@2.1"]),              # pinned pypi (uv shorthand)
    _entry(command="/usr/local/bin/some-server", args=[]),        # bare binary — skip, never guess
    {"url": "https://example.com/mcp"},                           # remote — no launch spec
])
def test_pinned_or_unrecognised_does_not_fire(entry):
    assert [f for f in check("s", entry) if f.kind == "config:unpinned-package"] == []


def test_unpinned_pypi_fires():
    kinds = [f.kind for f in check("s", {"command": "uvx", "args": ["example-pkg"], "env": {}})]
    assert kinds == ["config:unpinned-package"]


def test_tls_off_fires_only_on_zero():
    fired = check("s", _entry(env={"NODE_TLS_REJECT_UNAUTHORIZED": "0"}))
    assert [f.kind for f in fired] == ["config:tls-off"]
    for benign in ("1", "false", ""):
        assert check("s", _entry(env={"NODE_TLS_REJECT_UNAUTHORIZED": benign})) == []


def test_tls_off_names_co_resident_credentials_without_printing_them():
    fired = check("s", _entry(env={"NODE_TLS_REJECT_UNAUTHORIZED": "0", "JIRA_TOKEN": GHP}))
    tls = [f for f in fired if f.kind == "config:tls-off"]
    assert tls and "carries credentials" in tls[0].evidence
    assert GHP not in tls[0].evidence


def test_install_scripts_fires_on_allow_build_in_args_only():
    assert [f.kind for f in check("s", _entry(args=["-y", "example-pkg@1.0", "--allow-build"]))] \
        == ["config:install-scripts"]
    assert check("s", _entry(env={"FLAGS": "--allow-build"})) == []


@pytest.mark.parametrize("env", [
    {"GITHUB_TOKEN": GHP},                        # vendor-shaped literal
    {"API_KEY": OPAQUE},                          # credential-named, opaque value
])
def test_plaintext_credential_in_env_fires(env):
    fired = check("s", _entry(env=env))
    assert [f.kind for f in fired] == ["config:plaintext-credential"]


@pytest.mark.parametrize("env", [
    {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},          # expansion — indirection is the RIGHT pattern
    {"GITHUB_TOKEN": "$GITHUB_TOKEN"},
    {"GITHUB_TOKEN": "op://vault/github/token"},  # secret-manager reference
    {"SSH_KEY_FILE": "~/.ssh/id_ed25519"},        # a PATH to a credential
    {"API_KEY": "your-api-key-here"},             # placeholder
    {"API_KEY": ""},                              # empty
    {"TIMEOUT": "30"},                            # not credential-shaped at all
])
def test_credential_indirection_and_placeholders_do_not_fire(env):
    assert check("s", _entry(env=env)) == []


def test_authorization_header_literal_fires_but_expansion_does_not():
    fired = check("s", {"url": "https://x.example/mcp",
                        "headers": {"Authorization": f"Bearer {BEARER}"}})
    assert [f.kind for f in fired] == ["config:plaintext-credential"]
    assert "headers `Authorization`" in fired[0].evidence
    clean = check("s", {"url": "https://x.example/mcp",
                        "headers": {"Authorization": "Bearer ${API_TOKEN}"}})
    assert clean == []


def test_non_credential_header_with_opaque_value_does_not_fire():
    assert check("s", {"url": "https://x.example/mcp",
                       "headers": {"X-Trace-Id": OPAQUE}}) == []


# --- 2. REGISTRY canary: kinds, SHORT names, leads all stay in lock ------------------------------

POISON = _entry(command="npx",
                args=["-y", "example-pkg@latest", "--allow-build"],
                env={"NODE_TLS_REJECT_UNAUTHORIZED": "0", "GITHUB_TOKEN": GHP})


def test_every_registered_kind_fires_and_every_fired_kind_is_registered():
    fired = {f.kind for f in check("s", POISON)}
    assert fired == set(CONFIG_KINDS), (
        "CONFIG_KINDS and the detectors have drifted apart — a registered kind that never fires "
        "is dead weight; an unregistered kind escapes every renderer keyed on the registry.")


def test_every_kind_literal_in_source_is_registered():
    import inspect
    import re as _re
    from mcpgawk import configcheck as m
    literals = set(_re.findall(r'"(config:[a-z-]+)"', inspect.getsource(m)))
    assert literals == set(CONFIG_KINDS)


def test_every_kind_has_a_short_name_and_a_render_lead():
    assert set(SHORT) == set(CONFIG_KINDS)
    assert "config" in _SIGNAL_LEAD, "family fallback lead missing — findings would render " \
                                     "under 'review signal in' and be mislabelled"
    for kind in CONFIG_KINDS:
        assert kind in _SIGNAL_LEAD_BY_KIND, f"{kind} has no per-kind lead phrase"


# --- 3. EVIDENCE is value-free, on every poison fixture ------------------------------------------

def test_no_evidence_ever_contains_a_credential_value():
    entries = [POISON,
               _entry(env={"API_KEY": OPAQUE}),
               {"url": "https://x.example/mcp", "headers": {"Authorization": f"Bearer {BEARER}"}}]
    for entry in entries:
        for f in check("s", entry):
            for secret in (GHP, OPAQUE, BEARER):
                assert secret not in f.evidence, f"{f.kind} leaked a value into evidence"


# --- 4. Surfaces: fleet row, row state, panel rows ------------------------------------------------

def test_skipped_row_carries_findings_and_a_clean_entry_stays_terse():
    row = fleet.skipped_row("srv", POISON)
    assert row.state == "SKIPPED"                 # honesty: still not measured
    for phrase in ("unpinned version", "TLS verification off",
                   "install scripts allowed", "plaintext credential"):
        assert phrase in row.detail
    clean = fleet.skipped_row("srv", _entry())
    assert "config:" not in clean.detail and "⚠" not in clean.detail


def _label_with(kinds: list[str]) -> dict:
    return {"name": "srv", "x-mcpgawk": {
        "tool_count": 3, "cost_index_tokens": 100, "risk_flags": {}, "trust_surface": {},
        "bounded_signals": [{"kind": k, "tool": "srv", "evidence": "e"} for k in kinds]}}


def test_risky_config_kind_flips_row_to_review_but_unpinned_stays_clean():
    state, detail = fleet.state_of(_label_with(["config:tls-off"]))
    assert state == "REVIEW" and "1 config finding" in detail
    state, detail = fleet.state_of(_label_with(["config:unpinned-package"]))
    assert state == "CLEAN" and "1 config finding" in detail, (
        "unpinned is the ecosystem default — it must inform, not shout, or the fleet view "
        "trains the reader to stop looking")


def test_panel_rows_shape_and_severity_mapping():
    rows = panel._config_finding_rows({"srv": POISON})
    assert {r["code"] for r in rows} == set(CONFIG_KINDS)
    for r in rows:
        assert r["class"] == "config" and not r["first_party"] and not r["suppressed"]
        assert r["severity"] == ("medium" if r["code"] in RISKY_KINDS else "low")
    assert panel._config_finding_rows({"bad": None}) == []   # one bad entry never blanks the rest


# --- 5. THE ACCEPTANCE TEST: declined launches, then read the rendered surfaces -----------------

@pytest.fixture()
def fake_home(tmp_path, monkeypatch):
    """Discovery, history and behaviour all under tmp — the developer's real fleet must never
    reach these assertions (same shape as test_panel_renders_the_truth's `machine`)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MCPGAWK_HISTORY", str(tmp_path / "history.json"))
    monkeypatch.setenv("GAWK_BEHAVIOUR_PROFILE", str(tmp_path / "behaviour.json"))
    monkeypatch.setenv("MCPGAWK_NO_UPDATE_CHECK", "1")
    return tmp_path


TWO_BAD_SERVERS = {"mcpServers": {
    "jira": {"command": "npx", "args": ["-y", "example-jira@latest"],
             "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0", "JIRA_TOKEN": GHP}},
    "files": {"command": "pnpm", "args": ["dlx", "example-files", "--allow-build"], "env": {}},
}}


def test_scan_stdout_carries_config_findings_when_every_launch_is_declined(tmp_path, capsys):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps(TWO_BAD_SERVERS))

    cli.main(["scan", str(cfg)])                  # no --yes and no TTY: both servers declined

    out = capsys.readouterr().out
    assert "SKIPPED" in out
    for phrase in ("unpinned version", "TLS verification off",
                   "install scripts allowed", "plaintext credential"):
        assert phrase in out, f"declined-server stdout lost the {phrase!r} finding — the " \
                              f"tester's 'Findings 0' failure rebuilt"
    assert GHP not in out


def test_low_only_config_findings_inform_without_alarming(fake_home):
    """Founder call 2026-08-23: unpinned is the ecosystem's README default, so a fresh install
    must not boot to a red Findings badge or a 'open Findings and decide' next-best-action.
    The count stays visible; the alarm colour and the Next: slot are reserved for medium+."""
    _claude_desktop_config(fake_home).write_text(json.dumps(
        {"mcpServers": {"files": {"command": "npx", "args": ["-y", "example-files"],
                                  "env": {}}}}))

    page = panel.render(panel.collect(), token="T")

    assert "needing a decision" in page          # the count is still there…
    assert "ct alert" not in page, "a low-severity config finding turned a badge red"
    assert "open Findings and decide" not in page, \
        "low-only findings hijacked the next-best-action slot"


def test_medium_config_findings_do_alarm(fake_home):
    _claude_desktop_config(fake_home).write_text(json.dumps(TWO_BAD_SERVERS))

    page = panel.render(panel.collect(), token="T")

    assert "ct alert" in page                    # tls-off / plaintext-credential are medium
    assert "open Findings and decide" in page


def test_panel_page_shows_config_findings_with_nothing_ever_scanned(fake_home):
    _claude_desktop_config(fake_home).write_text(json.dumps(TWO_BAD_SERVERS))

    page = panel.render(panel.collect(), token="T")

    # The findings table renders class + evidence, so assert the evidence phrases as printed —
    # the rendered output, not the helper's field names.
    assert "certificate verification is off" in page
    assert "holds a literal credential" in page
    assert "needing a decision" in page, "the Findings count still reads as if nothing is wrong"
    assert GHP not in page, "the panel printed a credential value from the config"


def test_a_config_finding_survives_the_program_being_uninstalled():
    """A dangling entry must say WHAT it would run, not merely that it would run something.

    The row already reads "still configured, so anything at that path would run" — and until
    2026-09-02 it then withheld `--allow-build`, TLS-off and the plaintext credential, because
    `fleet.skipped_row` returned before the configcheck summary. Nothing in those findings depends
    on the program existing: they are read from the entry text, and a reinstall — or anything else
    landing at that path — runs under exactly this configuration.

    PINNED AT THE ROW, NOT THROUGH A SCAN, and deliberately. The four tests above reach this path
    only on a machine WITHOUT `pnpm`: green on the author's Mac, red in the public repo's Linux CI,
    which is the run that gates `twine upload`. An end-to-end version has a second environment
    dependency — with no other servers discoverable the listing renders no rows at all (a separate
    gap, see HANDOFF) — so it would go quiet again for a different reason. This calls the function
    that was wrong, with a command that exists nowhere, and is therefore the same test everywhere.
    """
    row = fleet.skipped_row("files", {"command": "mcpgawk-no-such-program-anywhere",
                                      "args": ["dlx", "example-files", "--allow-build"],
                                      "env": {}})
    assert row.state == "UNREACHABLE"
    assert "no longer exists" in row.detail
    assert "install scripts allowed" in row.detail, (
        "the row says anything at that path would run, then refuses to say what it would do")


def test_a_reachable_declined_server_still_reports_its_config():
    """The branch next door, so the two cannot drift: consent withheld is not ignorance."""
    row = fleet.skipped_row("files", {"command": "python3",
                                      "args": ["-m", "example", "--allow-build"], "env": {}})
    assert row.state == "SKIPPED"
    assert "install scripts allowed" in row.detail
