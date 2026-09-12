"""`mcpgawk changes` — what a server's tool surface did over time, from the local history.

Measured on the founder's real store 2026-09-12: five third-party servers changed nineteen times
in six weeks (resend gained `update-api-key`; Notion gained tools that spawn and message its own
agent sessions), every one approved in bulk seconds apart, and NO surface could show any of it
afterwards — `decide` shows only unapproved change and `baseline` only the current state. Once
you say yes, the history was write-only. This command reads it back.

Every assertion drives the real entry point (`cli.main`) against a store at `tmp_path`, and the
comparison is `drift.compare` — the same rule the scan's DRIFT block uses — so this screen can
never disagree with that one.
"""

from __future__ import annotations

import json

import pytest

from mcpgawk import cli, drift, history

T = "2026-09-0{d}T10:00:00+00:00"


def _rec(day: int, tools: dict[str, str], *, schemas: dict[str, str] | None = None,
         resources: dict[str, str] | None = None, enumerated=("tool", "resource"),
         texts: dict[str, str] | None = None) -> dict:
    items = {f"tool.{n}": h for n, h in tools.items()}
    items.update({f"resource.{n}": h for n, h in (resources or {}).items()})
    return {
        "measured_at": T.format(d=day),
        "pin": "".join(sorted(tools.values()))[:16].ljust(16, "0"),
        "pin_basis": drift.PIN_BASIS,
        "tools_basis": drift.TOOLS_BASIS,
        "schema_version": drift.RECORD_SCHEMA,
        "tools": dict(tools),
        "items": items,
        "texts": {f"tool.{n}": (texts or {}).get(n, f"{n} does {n}") for n in tools},
        "schemas": {f"tool.{n}": (schemas or {}).get(n, "s" + n) for n in tools},
        "annotations": {f"tool.{n}": {} for n in tools},
        "enumerated": list(enumerated),
        "cost_index": 100 * len(items),
        "transport": "stdio",
    }


A = {**_rec(1, {"read": "h-read"}), "login_id": "first-account"}
# B rewrites read's description AND its schema, adds a tool, and arrives under another sign-in —
# every tail branch of `render` that mentions approval fires on this pair.
B = {**_rec(2, {"read": "h-read-v2", "rotate_key": "h-rotate"}, schemas={"read": "s-read-v2"},
            texts={"read": "read does read, now also from the network"}),
     "login_id": "other-account"}
_AFTER_B = dict(tools={"read": "h-read-v2", "rotate_key": "h-rotate"}, schemas={"read": "s-read-v2"},
                texts={"read": "read does read, now also from the network"})
C = {**_rec(3, **_AFTER_B), "login_id": "other-account"}
D = {**_rec(4, **_AFTER_B, resources={"card": "h-card"}), "login_id": "other-account"}
E = {**_rec(5, **_AFTER_B, enumerated=("tool",)), "login_id": "other-account"}


@pytest.fixture
def store(tmp_path, monkeypatch):
    p = str(tmp_path / "history.json")
    monkeypatch.setenv(history.STORE_ENV, p)
    for r in (A, B, C, D, E):
        history.record("mcp:srv", r, path=p)
    st = history.load(p)
    st["servers"]["mcp:srv"]["aliases"] = ["srv"]
    history.save(st, p)
    return p


def _run(capsys, *argv) -> tuple[int, str]:
    rc = cli.main(["changes", *argv])
    return rc, capsys.readouterr().out


def test_a_real_change_names_the_tool_and_the_schema(store, capsys):
    rc, out = _run(capsys, "srv", "--since", "2026-08-01")
    assert rc == 0, out
    assert "rotate_key" in out and "added" in out, out
    assert "input schema CHANGED: read" in out, out


def test_an_identical_snapshot_is_not_a_change(store, capsys):
    _, out = _run(capsys, "srv", "--since", "2026-08-01")
    # A→B and C→D are the only comparable pairs that differ. B→C is byte-identical, and D→E
    # differs only in a kind E never enumerated (see the dadan test below) — neither may print.
    assert out.count("⟳") == 2, out
    assert T.format(d=3) not in out, "an identical snapshot printed as a change:\n" + out


def test_a_resource_added_with_no_tool_change_is_still_a_change(store, capsys):
    """The pin covers TOOLS only. Keying this screen on the pin would hide exactly the class the
    dadan false alarm came from — resources and prompts are two of the three injection surfaces."""
    _, out = _run(capsys, "srv", "--since", "2026-08-01")
    assert "card" in out and "resource" in out, out


def test_a_kind_one_side_never_asked_for_is_not_reported(store, capsys):
    """D→E: E enumerated tools only, so its missing resource is 'never asked', not 'removed'.
    This is the dadan regression: a partial snapshot must not accuse the server."""
    _, out = _run(capsys, "srv", "--since", "2026-08-01")
    assert "removed" not in out, out
    assert T.format(d=5)[:16] not in out.replace(" ", "T"), "D→E printed as a change:\n" + out


def test_since_narrows_the_window_but_keeps_the_record_before_it(store, capsys):
    _, out = _run(capsys, "srv", "--since", "2026-09-03T12:00:00+00:00")
    assert "rotate_key" not in out, "A→B is outside the window:\n" + out
    assert "card" in out, "C→D is the first change in the window; C sits before it and must still be the base:\n" + out


def test_json_is_one_entry_per_change(store, capsys):
    rc, out = _run(capsys, "srv", "--since", "2026-08-01", "--json")
    assert rc == 0
    data = json.loads(out)
    assert [e["at"] for e in data["changes"]] == [T.format(d=2), T.format(d=4)], data
    first = data["changes"][0]
    assert first["added"] == ["tool.rotate_key"] and first["schema_changed"] == ["tool.read"], first


def test_the_header_never_claims_an_approval(store, capsys):
    """Nothing here was approved. 'changed since you approved it' on this screen would be the
    same lie the scan told on 2026-09-12 ('since you approved it just now' with approved_at None)."""
    _, out = _run(capsys, "srv", "--since", "2026-08-01")
    # A→B fires every tail branch: a description rewrite ("before approving"), a sign-in change
    # ("your baseline was approved under"). None of that wording belongs on this screen.
    assert "Nothing in what changed" in out, "the fixture no longer exercises the tail:\n" + out
    assert "sign-in" in out, "the fixture no longer exercises the login branch:\n" + out
    assert "approv" not in out.lower(), out


def test_a_description_that_changed_past_what_the_store_keeps_says_so(tmp_path, monkeypatch, capsys):
    p = str(tmp_path / "history.json")
    monkeypatch.setenv(history.STORE_ENV, p)
    long = "x" * drift.MAX_TEXT
    before = _rec(1, {"read": "h-1"}, texts={"read": long})
    after = _rec(2, {"read": "h-2"}, texts={"read": long})   # same first MAX_TEXT chars, new hash
    history.record("mcp:srv", before, path=p)
    history.record("mcp:srv", after, path=p)
    _, out = _run(capsys, "mcp:srv", "--since", "2026-08-01")
    assert "description CHANGED" in out, out
    assert f"past the {drift.MAX_TEXT} characters the store kept" in out, out


def test_a_record_cut_at_the_old_limit_names_the_old_limit(tmp_path, monkeypatch, capsys):
    """MAX_TEXT rose 600 → 2000 on 2026-09-12. A record written before that holds 600 characters,
    and the screen must say 600 for it — the number is what WAS stored, not today's constant."""
    p = str(tmp_path / "history.json")
    monkeypatch.setenv(history.STORE_ENV, p)
    old_cut = "x" * 600
    history.record("mcp:srv", _rec(1, {"read": "h-1"}, texts={"read": old_cut}), path=p)
    history.record("mcp:srv", _rec(2, {"read": "h-2"}, texts={"read": old_cut}), path=p)
    _, out = _run(capsys, "mcp:srv", "--since", "2026-08-01")
    assert "past the 600 characters the store kept" in out, out
    assert str(drift.MAX_TEXT) not in out, out


def _two(tmp_path, monkeypatch, first: dict, second: dict) -> str:
    p = str(tmp_path / "history.json")
    monkeypatch.setenv(history.STORE_ENV, p)
    history.record("mcp:srv", first, path=p)
    history.record("mcp:srv", second, path=p)
    return p


def test_a_snapshot_that_never_said_what_it_enumerated_is_compared_on_tools_only(tmp_path, monkeypatch, capsys):
    """The dadan flip-flop, verbatim from the founder's store 2026-09-09: `wrap` records with no
    `enumerated` (tools only) interleaved with full probes, and the resource read as added and
    removed eleven times in a day. A record that cannot say which kinds it saw is compared on
    tools alone, and the screen says so."""
    wrap_style = {**_rec(1, {"read": "h"}), "enumerated": None}
    probe = _rec(2, {"read": "h"}, resources={"card": "h-card"})
    _two(tmp_path, monkeypatch, wrap_style, probe)
    rc, out = _run(capsys, "srv", "--since", "2026-08-01")
    assert rc == 0
    assert "card" not in out and "⟳" not in out, "a partial snapshot accused the server:\n" + out
    assert "tools only" in out and "1 comparison" in out, out


def test_both_screens_read_enumerated_through_one_function(tmp_path, monkeypatch, capsys):
    """`drift.kinds_spoken_for` is the one reader. Patch it and BOTH the changelog's policy and
    `comparable_kinds` must follow — if either kept a private reader, this stays quiet."""
    wrap_style = {**_rec(1, {"read": "h"}), "enumerated": None}
    probe = _rec(2, {"read": "h"}, resources={"card": "h-card"})
    _two(tmp_path, monkeypatch, wrap_style, probe)
    assert drift.kinds_spoken_for(wrap_style) is None
    assert drift.kinds_spoken_for({"enumerated": []}) is None
    assert drift.kinds_spoken_for(probe) == {"tool", "resource"}
    monkeypatch.setattr(drift, "kinds_spoken_for", lambda rec: {"tool", "resource"})
    assert drift.comparable_kinds(wrap_style, probe) == {"tool", "resource"}
    _, out = _run(capsys, "srv", "--since", "2026-08-01")
    assert "card" in out and "⟳" in out, "the changelog did not go through the one reader:\n" + out


def test_an_empty_enumerated_stamp_counts_as_not_speaking(tmp_path, monkeypatch, capsys):
    """wrap stamped `enumerated: []` between 0.1.40 and 0.1.41 — same meaning as absent."""
    wrap_style = {**_rec(1, {"read": "h"}), "enumerated": []}
    probe = _rec(2, {"read": "h"}, resources={"card": "h-card"})
    _two(tmp_path, monkeypatch, wrap_style, probe)
    _, out = _run(capsys, "srv", "--since", "2026-08-01")
    assert "⟳" not in out, out


def test_a_transport_or_protocol_difference_alone_is_not_a_change(tmp_path, monkeypatch, capsys):
    """`wrap` is a stdio bridge and stamps stdio for an http upstream; a second client negotiates
    another spec revision. Both are facts about the writer. Against an approval the scan must shout
    about them; between two snapshots they are not the server changing."""
    a = {**_rec(1, {"read": "h"}), "transport": "http", "protocol_version": "2025-11-25"}
    b = {**_rec(2, {"read": "h"}), "transport": "stdio", "protocol_version": "2024-11-05"}
    _two(tmp_path, monkeypatch, a, b)
    _, out = _run(capsys, "srv", "--since", "2026-08-01")
    assert "⟳" not in out, out
    assert "TRANSPORT" not in out and "protocol changed" not in out, out


def test_a_transport_difference_beside_a_real_change_is_noted_not_alarmed(tmp_path, monkeypatch, capsys):
    a = {**_rec(1, {"read": "h"}), "transport": "http"}
    b = {**_rec(2, {"read": "h", "rotate_key": "h2"}), "transport": "stdio"}
    _two(tmp_path, monkeypatch, a, b)
    _, out = _run(capsys, "srv", "--since", "2026-08-01")
    assert "rotate_key" in out, out
    assert "TRANSPORT changed" not in out and "recorded over stdio" in out, out


def test_a_longer_stored_text_after_the_limit_was_raised_is_not_a_change(tmp_path, monkeypatch, capsys):
    """MAX_TEXT went 600 → 2000 on 2026-09-12. Every record before that holds 600 characters; the
    first record after holds up to 2000 of the SAME description. The hash decides CHANGED, the
    text only shows it — so the longer text must not print as a rewrite."""
    full = "y" * 1500
    old = _rec(1, {"read": "h-same"}, texts={"read": full[:600]})
    new = _rec(2, {"read": "h-same"}, texts={"read": full})
    _two(tmp_path, monkeypatch, old, new)
    _, out = _run(capsys, "srv", "--since", "2026-08-01")
    assert "⟳" not in out, out


def test_no_server_means_every_server(store, capsys):
    rc, out = _run(capsys, "--since", "2026-08-01")
    assert rc == 0 and "srv" in out and "rotate_key" in out, out


def test_unknown_name_exits_2(store, capsys):
    rc, _ = _run(capsys, "nope")
    assert rc == 2


def test_an_unreadable_store_exits_4_not_0(tmp_path, monkeypatch, capsys):
    p = tmp_path / "history.json"
    p.write_text("{not json")
    monkeypatch.setenv(history.STORE_ENV, str(p))
    rc, out = _run(capsys, "--json")
    assert rc == 4, out
    assert "error" in json.loads(out)
