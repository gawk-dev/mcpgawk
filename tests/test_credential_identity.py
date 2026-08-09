"""Same server, two logins: approving one must never approve the other.

The bug this pins (reproduced 2026-08-09, deferred by the founder, picked up 2026-08-10): a server's
identity came only from the name the SERVER asserts, so the same binary configured twice with
different credentials — a work GitHub and a personal one, billing-dev and billing-prod — collapsed
onto one baseline. Approve the tools on one and the guard waved calls through on the other, a server
the user never reviewed.

Every test here drives the real writers (`history.record`, `baseline.publish`) and the real
enforcing reader (`guard_hook.approved_for`), never a hand-built store: the two readers have drifted
apart in this repo before.
"""
from __future__ import annotations

from pathlib import Path

from mcpgawk import history
from mcpgawk.guard_hook import approved_for
from mcpgawk.probe import ServerSnapshot

WORK = {"command": "npx", "args": ["-y", "gh-mcp"], "env": {"GITHUB_TOKEN": "ghp_work_aaa"}}
PERSONAL = {"command": "npx", "args": ["-y", "gh-mcp"], "env": {"GITHUB_TOKEN": "ghp_personal_bbb"}}
NO_LOGIN = {"command": "npx", "args": ["-y", "notes-mcp"]}


def _snap(name: str, entry: dict, asserted: str = "github-mcp") -> ServerSnapshot:
    """A snapshot as the scanner builds one: the CONFIG name the user typed, plus what the server
    asserted about itself, plus whatever identifies the login this entry uses."""
    from mcpgawk.probe import credential_fingerprint

    return ServerSnapshot(name=name, transport="stdio", protocol_version="2025-06-18",
                          server_info={"name": asserted},
                          credential_fingerprint=credential_fingerprint(entry))


def _rec(tools: dict[str, str]) -> dict:
    return {"pin": "p" + "".join(sorted(tools)), "tools": tools, "measured_at": "2026-08-10T00:00:00Z"}


# --------------------------------------------------------------------------- the reproduction


def test_two_logins_are_two_identities():
    """R2. Same asserted name, different credentials → different baselines."""
    work, personal = _snap("gh-work", WORK), _snap("gh-personal", PERSONAL)
    assert history.key_for(work) != history.key_for(personal)


def test_a_call_is_judged_against_its_own_accounts_baseline(tmp_path: Path):
    """R1 — THE BUG. Two separate scans (the case the within-scan collision fallback cannot see),
    then a human approves the WORK account. The guard must judge a call on the personal account
    against the personal server's own surface — never against the one the human reviewed.

    Note what this does NOT claim: a server that has been scanned always has a baseline, because
    first sighting is trust-on-first-use by design (ADR-0012). The defect is not that the personal
    account has one — it is WHOSE it is. Before the fix both entries shared a single record, so
    approving work moved the personal account's baseline too: `deploy` (which the personal server
    actually offers and nobody reviewed) vanished from it, and `list_repos` was blessed there on the
    strength of a review of a different account.
    """
    from mcpgawk import baseline

    store = tmp_path / "history.json"
    work, personal = _snap("gh-work", WORK), _snap("gh-personal", PERSONAL)

    history.record(history.key_for(work), _rec({"list_repos": "h1"}),
                   path=str(store), alias=work.name)
    history.record(history.key_for(personal), _rec({"deploy": "h9"}),
                   path=str(store), alias=personal.name)
    baseline.publish(history.key_for(work), pin="p1", tools={"list_repos": "h1"},
                     approved_at="2026-08-10T00:00:00Z", alias=work.name, path=str(store))

    assert approved_for("gh-work", store) == {"list_repos": "h1"}, "sanity: the approved one enforces"
    assert approved_for("gh-personal", store) == {"deploy": "h9"}, (
        "the personal account must be judged against the personal server — approving the work "
        "account must not reach across to it")


def test_each_login_keeps_its_own_history(tmp_path: Path):
    """The same collision seen from the drift side: recording the second account must not diff it
    against the first account's baseline, which reported a rug-pull that never happened on every
    scan — and an alarm that fires forever is one the user learns to ignore."""
    store = tmp_path / "history.json"
    work, personal = _snap("gh-work", WORK), _snap("gh-personal", PERSONAL)

    history.record(history.key_for(work), _rec({"list_repos": "h1"}), path=str(store), alias=work.name)
    previous = history.record(history.key_for(personal), _rec({"deploy": "h9"}),
                              path=str(store), alias=personal.name)
    assert previous is None, ("the personal account has never been seen before — it is a first "
                              "sighting, not a diff against the work account")


def test_a_server_with_no_login_keeps_its_existing_identity():
    """R3. The carve-out that makes this safe to ship: entries carrying no credentials key exactly
    as before, so no existing baseline is disturbed on upgrade."""
    plain = _snap("notes", NO_LOGIN, asserted="notes-pro")
    assert history.key_for(plain) == "mcp:notes-pro"


def test_the_key_never_carries_the_credential(tmp_path: Path):
    """R5. The key lands in history.json and in the guard projection, both on disk. It must be a
    digest of the login, never the login."""
    key = history.key_for(_snap("gh-work", WORK))
    assert "ghp_work_aaa" not in key
    assert "GITHUB_TOKEN" not in key


def test_the_fingerprint_is_stable_across_runs():
    """A per-run salt would re-identify every server on every scan — a drift alarm that fires
    forever, which trains the user to ignore the one signal that matters."""
    from mcpgawk.probe import credential_fingerprint

    assert credential_fingerprint(WORK) == credential_fingerprint(dict(WORK))
    assert credential_fingerprint(NO_LOGIN) is None


# --------------------------------------------------------------------------- the migration window


def test_the_first_claimant_adopts_the_old_baseline(tmp_path: Path):
    """Upgrade path. A pre-upgrade store has ONE conflated record under `mcp:<asserted>`. The first
    entry re-scanned adopts it — losing people's approvals is the worse failure."""
    store = tmp_path / "history.json"
    work = _snap("gh-work", WORK)
    history.record("mcp:github-mcp", _rec({"list_repos": "h1"}), path=str(store), alias="gh-work")

    previous = history.record(history.key_for(work), _rec({"list_repos": "h1"}), path=str(store),
                              alias=work.name,
                              migrate_from=history.legacy_identity_keys(work))
    assert previous is not None, "the existing approval must move onto the new key, not be orphaned"
    assert "mcp:github-mcp" not in history.load(str(store))["servers"]


def test_the_other_login_does_not_inherit_through_the_migration(tmp_path: Path):
    """R4 — the bug surviving its own fix. The conflated record carries BOTH config names as
    aliases. If adoption keeps them, the guard's alias lookup for the not-yet-rescanned entry still
    single-matches the adopted record and enforces the wrong baseline until it is scanned again."""
    from mcpgawk import baseline

    store = tmp_path / "history.json"
    history.record("mcp:github-mcp", _rec({"list_repos": "h1"}), path=str(store), alias="gh-work")
    history.record("mcp:github-mcp", _rec({"list_repos": "h1"}), path=str(store), alias="gh-personal")
    baseline.publish("mcp:github-mcp", pin="p1", tools={"list_repos": "h1"},
                     approved_at="2026-08-10T00:00:00Z", path=str(store))

    work = _snap("gh-work", WORK)
    history.record(history.key_for(work), _rec({"list_repos": "h1"}), path=str(store),
                   alias=work.name, migrate_from=history.legacy_identity_keys(work))

    assert approved_for("gh-work", store) == {"list_repos": "h1"}, "sanity: the claimant is enforced"
    assert approved_for("gh-personal", store) is None, (
        "the entry that has not been re-scanned must defer — it inherited an alias, not a review")


def test_a_credential_free_sibling_keeps_its_own_baseline(tmp_path: Path):
    """The migration's own version of the bug it fixes. `mcp:<asserted>` is not only a LEGACY key —
    it stays the live identity of any entry that carries no login. A credentialled entry asserting
    the same name must not adopt it: that would destroy a real baseline AND enforce one account's
    approval against another, which is exactly what this change exists to stop.

    Real shape: one GitHub entry on ambient `gh` auth, one with a GITHUB_TOKEN in `env`.
    """
    store = tmp_path / "history.json"
    ambient = _snap("gh-ambient", NO_LOGIN, asserted="github-mcp")
    assert history.key_for(ambient) == "mcp:github-mcp", "sanity: no login, so the bare key IS live"
    history.record(history.key_for(ambient), _rec({"list_repos": "h1"}),
                   path=str(store), alias=ambient.name)

    tokened = _snap("gh-token", WORK)
    previous = history.record(history.key_for(tokened), _rec({"deploy": "h9"}), path=str(store),
                              alias=tokened.name,
                              migrate_from=history.legacy_identity_keys(tokened))

    servers = history.load(str(store))["servers"]
    assert "mcp:github-mcp" in servers, "the ambient entry's live baseline was taken from it"
    assert servers["mcp:github-mcp"]["aliases"] == ["gh-ambient"]
    assert previous is None, "the token entry has never been seen — a first sighting, not an adoption"
    assert approved_for("gh-ambient", store) == {"list_repos": "h1"}


def test_a_conflated_record_is_still_adoptable(tmp_path: Path):
    """The other side of that guard: attribution is by ALIAS, so a genuinely conflated pre-upgrade
    record — which names the claiming entry, because every tracked scan records its config name —
    is still adopted rather than orphaned. Pinned so tightening the guard cannot quietly turn the
    upgrade path into a fleet-wide approval reset."""
    store = tmp_path / "history.json"
    history.record("mcp:github-mcp", _rec({"list_repos": "h1"}), path=str(store), alias="gh-work")
    work = _snap("gh-work", WORK)
    previous = history.record(history.key_for(work), _rec({"list_repos": "h1"}), path=str(store),
                              alias=work.name, migrate_from=history.legacy_identity_keys(work))
    assert previous is not None and "mcp:github-mcp" not in history.load(str(store))["servers"]


# --------------------------------------------------------------------------- the write side


def test_approve_refuses_an_ambiguous_name(tmp_path: Path):
    """`resolve` used to take the first alias match, so `mcpgawk approve billing` could move a
    baseline the operator never looked at — the write-side twin of the ambiguity the enforcing
    reader already defers on. Aliases are known to collide here (every `--stdio` scan is labelled
    `cli-stdio`), so this is routine, not exotic."""
    store = {"servers": {"mcp:a": {"aliases": ["billing"]}, "mcp:b": {"aliases": ["billing"]}}}
    assert history.resolve(store, "billing") is None
    assert sorted(history.resolve_all(store, "billing")) == ["mcp:a", "mcp:b"]
    # An unambiguous name still resolves — the refusal must not be "never resolve an alias".
    assert history.resolve({"servers": {"mcp:a": {"aliases": ["billing"]}}}, "billing") == "mcp:a"


def test_the_approve_command_names_the_candidates(tmp_path: Path, capsys, monkeypatch):
    """A refusal an operator cannot act on is a dead end: it must print the keys to choose between."""
    import json

    from mcpgawk import cli, history as h

    store = tmp_path / "history.json"
    monkeypatch.setenv("MCPGAWK_HISTORY", str(store))
    for key in ("mcp:a", "mcp:b"):
        h.record(key, _rec({"t": "h1"}), path=str(store), alias="billing")
    # Both records must genuinely be waiting, or `approve` never reaches the resolve step.
    assert len(json.loads(store.read_text())["servers"]) == 2

    code = cli.main(["approve", "billing"])
    err = capsys.readouterr().err
    assert code == 2
    assert "matches 2 tracked servers" in err
    assert "mcpgawk approve mcp:a" in err and "mcpgawk approve mcp:b" in err


# --------------------------------------------------------------------------- the shipped command


def test_the_upgrade_does_not_cry_wolf_about_a_lost_baseline(tmp_path: Path, monkeypatch, capsys):
    """Drives `mcpgawk scan --track` against a REAL server, on a store recorded under the old
    identity — the upgrade every existing user gets.

    Our key scheme changed; the server did not. `record` adopts the old record, so the baseline DOES
    carry over — but `identity_change` sees the config name resolving to a new key and, unguarded,
    the scan announces "now identifies itself as a DIFFERENT server … its baseline does not carry
    over". Observed on the real binary. That message is FALSE here and would fire once for every
    credentialled server on upgrade; a security tool that cries wolf on upgrade teaches people to
    ignore the one message that matters.
    """
    import json
    import sys

    from mcpgawk import cli

    fixture = str(Path(__file__).parent / "fixtures" / "toy_mcp_server.py")   # asserts "toy-fixture"
    store = tmp_path / "history.json"
    monkeypatch.setenv("MCPGAWK_HISTORY", str(store))
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"gh-work": {
        "command": sys.executable, "args": [fixture], "env": {"GITHUB_TOKEN": "ghp_work"}}}}))

    # The pre-upgrade store: keyed on the asserted name alone, carrying this entry's config name.
    history.record("mcp:toy-fixture", _rec({"read_inbox": "h1"}), path=str(store), alias="gh-work")

    # Exit 1 is CORRECT here and is not what this test is about: the seeded baseline lists one tool
    # and the live fixture has eight, so the adopted baseline produces real drift — which is the
    # product working. What must not happen is the scan claiming the baseline was lost.
    assert cli.main(["scan", str(cfg), "--track", "--yes", "--json"]) in (0, 1)
    out = capsys.readouterr().out
    assert "does not carry over" not in out, "the upgrade claimed a baseline was lost that was not"
    assert "reidentified_from" not in out or '"reidentified_from": null' in out
    assert "drift" in out.lower(), "sanity: the adopted baseline WAS compared against — not a first sighting"

    servers = history.load(str(store))["servers"]
    assert list(servers) == ["mcp:toy-fixture#" + _fp_of({"env": {"GITHUB_TOKEN": "ghp_work"}})]
    assert servers[list(servers)[0]]["approved"]["tools"] == {"read_inbox": "h1"}, (
        "the approval the user already gave must survive the upgrade")


def _fp_of(entry: dict) -> str:
    from mcpgawk.credentials import fingerprint

    fp = fingerprint(entry)
    assert fp
    return fp
