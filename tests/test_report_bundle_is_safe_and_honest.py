"""`mcpgawk report` — the two things that must hold, and one that must never regress.

1. **It carries the diagnosis and none of the tester's data.** This bundle leaves a
   stranger's machine and arrives in our inbox; a redaction miss is a stranger's data we
   now hold and nobody ever finds out. Every test here plants a KNOWN secret and asserts
   its absence, rather than asking a detector whether the output looks clean — a detector
   that under-matches would pass this file while leaking.

2. **It works in every machine state.** The bundle we most need is the one from the broken
   machine: no state directory, a corrupt store, a collector that raises. None of those may
   crash the command, and each must be reported as `unavailable` — which means NOBODY
   LOOKED, and must never be rendered as "nothing there".
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from mcpgawk import report
from mcpgawk.report_redact import redact_record, scrub_paths

SECRET = "sk-ant-api03-LIVEKEYAAAABBBBCCCCDDDDEEEEFFFF"
HOLDINGS = "RELIANCE 500 shares at 2841"
OAUTH_CODE = "AUTHCODE-abc123-should-never-ship"


def _bundle_text(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        return "\n".join(
            archive.read(name).decode("utf-8", "replace") for name in archive.namelist()
        )


@pytest.fixture(autouse=True)
def _default_mode():
    """Mode is process state; reset it so one test cannot decide another's expectations."""
    from mcpgawk import report_redact

    report_redact.set_strict(False)
    yield
    report_redact.set_strict(False)


@pytest.fixture()
def machine(tmp_path, monkeypatch):
    """A machine with a verify run that saw a secret, a token URL and a user's holdings."""
    home = tmp_path / "home"
    (home / ".gawk").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GAWK_BEHAVIOUR_PROFILE", str(home / ".gawk" / "behaviour.json"))
    monkeypatch.setenv("MCPGAWK_SPOOL", str(home / ".mcpgawk" / "calls.jsonl"))

    run_dir = home / ".gawk" / "verify-runs" / "2026-08-19T10-00-00Z"
    run_dir.mkdir(parents=True)
    (run_dir / "audit.jsonl").write_text("\n".join(json.dumps(r) for r in [
        {"type": "raw-observation", "server": "kite", "tool": "get_holdings", "ok": True,
         "code": "undeclared-egress",
         "resultTextExcerpt": HOLDINGS,
         "egress": [{"host": "api.kite.trade:443", "allowed": False}]},
        {"type": "auth-needed", "server": "kite",
         "url": f"https://auth.kite.trade/callback?code={OAUTH_CODE}&state=xyz"},
        {"type": "raw-observation", "server": "notes", "tool": "read",
         "infraDetail": f"failed with token={SECRET} at /Users/susha/.npm/x.js"},
    ]) + "\n", encoding="utf-8")
    return home


def test_a_servers_response_never_reaches_the_bundle(machine, tmp_path):
    """What a tester's MCP server RETURNED is their data — trades, notes, mail.

    Dropped by field name, not by inspection: a value that does not look sensitive to a
    detector is still the tester's.
    """
    dest = tmp_path / "r.zip"
    assert report.run(output=str(dest)) == 0
    text = _bundle_text(dest)

    assert HOLDINGS not in text, "a server response reached the bundle"
    assert SECRET not in text, "a credential reached the bundle"
    assert OAUTH_CODE not in text, "an OAuth authorisation code reached the bundle"
    # and the DIAGNOSIS survived — a bundle that redacts everything is useless
    assert "undeclared-egress" in text
    assert "api.kite.trade:443" in text
    assert "get_holdings" in text


def test_a_beta_grant_in_the_environment_never_reaches_the_bundle(machine, tmp_path, monkeypatch):
    """The likeliest credential on a beta tester's machine is one WE told them to export.

    `GAWK_BETA_KEY` is how a grant is delivered, and a signed grant is just text — no
    detector recognises it. So env values are masked by structure and only path-valued
    overrides survive, because those are the ones that actually explain the machine.

    This bundle gets pasted into issues, not only emailed.
    """
    grant = "gawk-beta.susha|2026-09-18.0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    monkeypatch.setenv("GAWK_BETA_KEY", grant)
    monkeypatch.setenv("GAWK_LICENSE_KEY", SECRET)
    monkeypatch.setenv("GAWK_MONITOR_DB", str(machine / ".gawk" / "monitor.db"))

    dest = tmp_path / "env.zip"
    assert report.run(output=str(dest)) == 0
    text = _bundle_text(dest)

    assert grant not in text, "a beta grant reached the bundle"
    assert SECRET not in text, "a licence key reached the bundle"
    # the NAMES are the diagnosis and must survive, and a path override still shows its path
    assert "GAWK_BETA_KEY" in text and "GAWK_LICENSE_KEY" in text
    assert "monitor.db" in text


def test_the_default_bundle_stays_comprehensive(machine, tmp_path):
    """The beta exists to ship a production-grade product, and that needs the whole picture.

    Guarding the DEFAULT explicitly, because the failure mode here is mine: it is always
    tempting to redact one more field, and each one silently costs a bug we can no longer
    diagnose. Removing an identifier from the default is a product decision, not a tidy-up,
    and this test is what makes it a deliberate one.
    """
    dest = tmp_path / "full.zip"
    assert report.run(output=str(dest)) == 0
    text = _bundle_text(dest)
    assert "api.kite.trade" in text, "egress destinations are the finding, not noise"
    assert "get_holdings" in text and "undeclared-egress" in text


def test_a_regulated_testers_server_command_never_leaves_their_machine():
    """A real beta tester's config, from a large healthcare enterprise, under --strict.

    One `stdio:` target names their internal MCP endpoint, their Okta client id and their
    private artifactory host. None of that is a credential, and no detector would flag it —
    but a tester at a regulated company cannot email it, so a bundle that carries it is a
    bundle that never gets sent, and the feature does not exist for the buyers it was built
    for. Allow-list, not deny-list: a token survives only if it cannot identify anyone.
    """
    from mcpgawk.report_redact import redact_command, set_strict

    set_strict(True)
    out = redact_command(
        'stdio:npx -y mcp-remote https://mcp-atlassian-server.srv.acme.io/mcp/ 8085 '
        '--static-oauth-client-info {"client_id":"0oazmbclz7cmBZnR8297"} '
        '--header X-Jira-Token: ${JIRA_PERSONAL_TOKEN}')
    for identifier in ("mcp-atlassian-server", "srv.acme.io", "0oazmbclz7cmBZnR8297"):
        assert identifier not in out, f"{identifier} reached the bundle"
    # the diagnosis survives: what runs it, that it proxies over https, which flags, which env
    assert "npx" in out and "https-url" in out
    assert "--static-oauth-client-info" in out
    assert "${JIRA_PERSONAL_TOKEN}" in out, "an env REFERENCE is not a secret and is diagnostic"

    unpinned = redact_command("stdio:pnpm dlx @acme/ide-jira-mcp@latest stdio")
    assert "acme" not in unpinned
    assert "@latest" in unpinned, "whether a package is pinned is the security finding"


def test_an_oauth_callback_is_not_safe_just_because_its_parameters_look_innocent():
    """`redact.redact_url` masks SECRET-NAMED parameters; `code` and `state` are neither.

    This is why the report does not use it. Kept as a test because the tempting
    simplification — "reuse the existing url redactor" — reintroduces the leak.
    """
    out = redact_record({"url": f"https://h/cb?code={OAUTH_CODE}&state=xyz"})["url"]
    assert OAUTH_CODE not in out
    assert "code=" in out, "parameter NAMES are the diagnosis and must survive"


def test_the_person_is_removed_even_when_the_path_is_mangled():
    """The username reaches logs in shapes that are not paths.

    A scratchpad directory encodes `/Users/name/x` as `-Users-name-x`; a path regex alone
    walks straight past it. Found by auditing a real bundle, not by review.
    """
    import getpass

    user = getpass.getuser()
    if len(user) < 4:
        pytest.skip("username too short to strike as a literal — path scrubbing only")
    assert user not in scrub_paths(f"/private/tmp/x/-Users-{user}-devtools/y")
    assert user not in scrub_paths(f"/Users/{user}/.npm/x.js")


def test_strict_mode_names_no_host_of_theirs_anywhere(machine, tmp_path):
    """Under --strict: the claim a security team can verify in one grep.

    Not "we remove the sensitive ones" — a tester cannot audit that, and neither can their
    reviewer. Every non-loopback host goes. Loopback stays because it describes OUR
    plumbing ("the gateway was listening"), not their estate.
    """
    import re

    dest = tmp_path / "hosts.zip"
    assert report.run(output=str(dest), strict=True) == 0
    urls = set(re.findall(r"[a-z]+://[^\s\"'<>,;)}\]]+", _bundle_text(dest)))
    leaked = [u for u in urls
              if not re.match(r"^[a-z]+://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])", u)]
    assert not leaked, f"the bundle names hosts the tester's employer runs: {leaked}"


def test_a_fresh_machine_produces_a_bundle_and_not_a_crash(tmp_path, monkeypatch):
    """The state a beta tester is actually in when they first hit trouble.

    Nothing installed, nothing ever run. Every store must report `unavailable` with a
    reason, and the command must still exit 0 — a diagnostic tool that dies on the machine
    it was written for is worth nothing.
    """
    home = tmp_path / "empty"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GAWK_BEHAVIOUR_PROFILE", str(home / ".gawk" / "behaviour.json"))
    monkeypatch.setenv("MCPGAWK_SPOOL", str(home / ".mcpgawk" / "calls.jsonl"))

    dest = tmp_path / "fresh.zip"
    assert report.run(output=str(dest)) == 0
    assert dest.exists()

    with zipfile.ZipFile(dest) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    states = {s["name"]: s["state"] for s in manifest["sections"]}
    assert states["verify-runs"] == report.UNAVAILABLE
    assert states["monitor-alerts"] == report.UNAVAILABLE
    for section in manifest["sections"]:
        if section["state"] == report.UNAVAILABLE:
            assert section["detail"], f"{section['name']} is unavailable without saying why"


def test_a_collector_that_raises_costs_only_its_own_section(machine, tmp_path, monkeypatch):
    """One broken store must not cost the other nine.

    The machines we most need a bundle from are the ones where something is already broken.
    """
    def boom():
        raise RuntimeError("the store is corrupt")

    monkeypatch.setattr(report, "_runs", boom)
    dest = tmp_path / "partial.zip"
    assert report.run(output=str(dest)) == 0

    with zipfile.ZipFile(dest) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        names = archive.namelist()
    states = {s["name"]: s for s in manifest["sections"]}
    assert states["runs"]["state"] == report.UNAVAILABLE
    assert "RuntimeError" in states["runs"]["detail"]
    assert "status.txt" in names and "environment.json" in names


def test_unavailable_is_never_rendered_as_nothing_there(tmp_path, monkeypatch):
    """The whole point of the manifest.

    A section nobody could read must never print as an all-clear or a zero. This is the
    bug class this codebase spent a session removing from every other surface; the command
    that reports on all of them must not reintroduce it.
    """
    home = tmp_path / "empty2"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GAWK_BEHAVIOUR_PROFILE", str(home / ".gawk" / "behaviour.json"))
    monkeypatch.setenv("MCPGAWK_SPOOL", str(home / ".mcpgawk" / "calls.jsonl"))

    bundle = report.collect()
    summary = report.render_summary(bundle)
    assert "unavailable" in summary
    assert "NOBODY LOOKED" in summary
    for section in bundle.sections:
        if section.state == report.UNAVAILABLE:
            assert section.records is None, (
                f"{section.name} could not be read but carries a count of "
                f"{section.records} — a number nobody measured"
            )
