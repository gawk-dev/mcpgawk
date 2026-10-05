"""The guard hook must resolve a server name exactly as `history.resolve` does — over EVERY record.

THE DEFECT THIS PINS (found by tests/test_differential_duplicates.py, pair 5). The hook resolves the
name in an agent's `mcp__<name>__<tool>` over the PROJECTION (guard-baseline.json), and the
projection held APPROVED records only. So when `<name>` is the key of a record nobody approved
(`history.resolve` -> `mcp:<name>`, no baseline) while some OTHER approved record carries `<name>`
as a config-name alias, the hook could not see the first record and fell through to the alias:

  * strict mode: it judged the call against the other server's baseline and let it through (or,
    with two such aliases, deferred as "ambiguous") — a call to a never-approved server PERMITTED
    where the in-process verdict refuses it. That is a bypass of strict mode.
  * normal mode: it denied calls on the strength of a baseline that belongs to another server.

Every test drives the canonical writer (`history.save`, which regenerates the projection) and the
real enforcing reader (`guard_hook.decide`); none hand-builds a projection from scratch.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpgawk import decision, guard_hook, history

SIGHTING = {"pin": "p1", "tools": {"read": "aaaaaaaaaaaa"}, "items": {"tool.read": "aaaaaaaaaaaa"},
            "tools_basis": 1, "measured_at": "2026-10-01T00:00:00+00:00"}


@pytest.fixture(autouse=True)
def _no_behaviour(tmp_path, monkeypatch):
    """No behavioural profile: these are declared-tier decisions only."""
    monkeypatch.setenv("GAWK_BEHAVIOUR", str(tmp_path / "absent-behaviour.json"))


def _approved(aliases: list[str]) -> dict:
    return {"aliases": aliases, "history": [dict(SIGHTING)], "approved": dict(SIGHTING),
            "approved_at": "2026-09-30T00:00:00+00:00"}


def _unapproved(aliases: list[str]) -> dict:
    return {"aliases": aliases, "history": [dict(SIGHTING)]}


def _save(tmp_path: Path, servers: dict, *, strict: bool) -> Path:
    path = tmp_path / "history.json"
    store = {"servers": servers}
    if strict:
        store["guard"] = {"strict": True}
    history.save(store, str(path))
    return path


def _call(path: Path, server: str, tool: str = "read"):
    return guard_hook.decide({"tool_name": f"mcp__{server}__{tool}", "tool_input": {}}, path)


def _as_old_projection(path: Path) -> None:
    """Rewrite the projection as a build from BEFORE the identity map would have: approved rows
    only, schema /1. The `source` stamp is untouched, so the hook still reads it as fresh."""
    proj = Path(history.projection_path(str(path)))
    raw = json.loads(proj.read_text(encoding="utf-8"))
    raw.pop("identities", None)
    raw.pop("placeholder_names", None)
    raw["schema"] = "gawk.guard-projection/1"
    proj.write_text(json.dumps(raw), encoding="utf-8")


# --------------------------------------------------------------------------- the bypass


def test_strict_refuses_a_never_approved_server_shadowed_by_another_servers_alias(tmp_path):
    """THE BYPASS. `mcp:x` was never approved; `stdio:x` (a different server) is approved and
    answers to the config name `x`. `history.resolve('x')` is `mcp:x` — no baseline — so strict
    mode must refuse the call. Before the fix the hook judged it against `stdio:x` and let it run."""
    path = _save(tmp_path, {"mcp:x": _unapproved([]), "stdio:x": _approved(["x"])}, strict=True)
    assert history.resolve(history.load(str(path)), "x") == "mcp:x"
    output, _note = _call(path, "x")
    assert output is not None, "strict mode let a call to a never-approved server through"
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert decision.strict_no_baseline_reason("x", "read") in \
        output["hookSpecificOutput"]["permissionDecisionReason"]


def test_strict_refuses_a_never_approved_server_shadowed_by_two_aliases(tmp_path):
    """Same, with TWO approved records answering to `x`: the hook used to defer as 'ambiguous',
    which in strict mode is the same permit."""
    path = _save(tmp_path, {"mcp:x": _unapproved([]), "mcp:beta": _approved(["x"]),
                            "mcp:gamma": _approved(["x"])}, strict=True)
    output, _note = _call(path, "x")
    assert output is not None, "strict mode deferred on a never-approved server"


def test_strict_refuses_a_name_that_is_ambiguous_in_history_resolve(tmp_path):
    """No record is keyed `x`; two approved records answer to it. `history.resolve` refuses the
    name (None: no baseline can be shown to apply), so strict mode refuses the call. Deferring
    'loudly' is still a permit."""
    path = _save(tmp_path, {"mcp:beta": _approved(["x"]), "mcp:gamma": _approved(["x"])},
                 strict=True)
    assert history.resolve(history.load(str(path)), "x") is None
    output, _note = _call(path, "x")
    assert output is not None, "strict mode deferred on a name history.resolve refuses"


def test_normal_mode_still_consults_an_approved_alias_records_baseline(tmp_path):
    """The non-strict face. `resolve('x')` is the never-approved `mcp:x` (defer), but `stdio:x` is
    approved and answers to `x`, so the agent may be calling it: its baseline still refuses a tool
    it never had, and the reason says whose baseline that was. A tool every candidate allows (or
    none can judge) passes. (0673f685 deferred `write` here; the hook only ever adds denials.)"""
    path = _save(tmp_path, {"mcp:x": _unapproved([]), "stdio:x": _approved(["x"])}, strict=False)
    output, _note = _call(path, "x", "write")
    assert output is not None
    assert "'stdio:x'" in output["hookSpecificOutput"]["permissionDecisionReason"]
    assert _call(path, "x", "read")[0] is None


# --------------------------------------------------------------------------- an OLD projection


def test_strict_fails_closed_on_an_old_projection_that_cannot_rule_out_the_shadow(tmp_path):
    """A projection written before the identity map existed holds approved records only, so an
    ALIAS hit on it cannot be shown to be what `history.resolve` would pick. In strict mode that
    uncertainty is a refusal, never a pass."""
    path = _save(tmp_path, {"mcp:x": _unapproved([]), "stdio:x": _approved(["x"])}, strict=True)
    _as_old_projection(path)
    output, note = _call(path, "x")
    assert output is not None, "strict mode trusted an alias hit on an old projection"
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_strict_on_an_old_projection_still_allows_an_exact_identity_hit(tmp_path):
    """The fail-closed rule is scoped to what an old projection cannot prove. A name that IS the
    approved record's own `mcp:<name>` identity wins in `history.resolve` before any alias is
    consulted, so it is enforced as before — not refused."""
    path = _save(tmp_path, {"mcp:x": _approved([])}, strict=True)
    _as_old_projection(path)
    output, _note = _call(path, "x")
    assert output is None


# --------------------------------------------------------------------------- most restrictive wins


def _credential_store(tmp_path: Path, *, strict: bool) -> Path:
    """The credential-discriminator shape: `mcp:x#…` (a login-bearing entry whose CONFIG name is
    `x`) is approved; a credential-free twin asserting the same name, `mcp:x`, is not.
    `history.resolve('x')` lands on `mcp:x` (asserted name before alias, by its documented rule),
    yet the agent calling `mcp__x__…` may well be talking to the approved one."""
    return _save(tmp_path, {"mcp:x#0123456789ab": _approved(["x"]),
                            "mcp:x": _unapproved(["x-personal"])}, strict=strict)


def test_an_approved_alias_candidate_still_denies_what_its_baseline_refuses(tmp_path):
    """THE HOOK ONLY EVER ADDS DENIALS. Resolving like `history.resolve` must not cost the
    protection the approved alias record gave: a tool absent from `mcp:x#…`'s baseline is denied
    even though `resolve` picks the never-approved `mcp:x` (normal mode, which defers on that)."""
    path = _credential_store(tmp_path, strict=False)
    output, _note = _call(path, "x", "evil")
    assert output is not None, "an approved server's baseline stopped guarding its alias"
    reason = output["hookSpecificOutput"]["permissionDecisionReason"]
    assert "mcp:x#0123456789ab" in reason, "the deny must name whose baseline refused it"


def test_the_credential_shape_in_both_modes(tmp_path):
    """The full table: normal mode passes `read` (no baseline refuses it) and denies `evil`;
    strict mode denies both (`resolve` picks a never-approved record)."""
    normal = _credential_store(tmp_path / "n", strict=False)
    strict = _credential_store(tmp_path / "s", strict=True)
    assert _call(normal, "x", "read")[0] is None
    assert _call(normal, "x", "evil")[0] is not None
    assert _call(strict, "x", "read")[0] is not None
    assert _call(strict, "x", "evil")[0] is not None
