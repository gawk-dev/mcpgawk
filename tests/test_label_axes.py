"""The 5-axis report: top_heavy_tools / trust_surface / annotation_completeness / coverage,
plus the opt-in supply_chain / oauth_scopes rendering branches in render_cli."""
from __future__ import annotations

from mcpgawk import build_label, measure
from mcpgawk.label import render_cli
from mcpgawk.probe import ServerSnapshot


def _snap(tools, prompts=None, resources=None):
    return ServerSnapshot(name="t", transport="stdio", protocol_version="x", tools=tools,
                          prompts=prompts or [], resources=resources or [])


def _label(tools, prompts=None, resources=None):
    snap = _snap(tools, prompts, resources)
    return build_label(snap, measure(snap))


def test_top_heavy_tools_sorted_desc_capped_at_3():
    tools = [{"name": f"t{i}", "description": "x" * (i * 20)} for i in range(5)]
    x = _label(tools)["x-mcpgawk"]
    heavy = x["top_heavy_tools"]
    assert len(heavy) == 3
    assert [h["tokens"] for h in heavy] == sorted((h["tokens"] for h in heavy), reverse=True)
    assert heavy[0]["name"] == "t4"          # the longest description => most tokens


def test_trust_surface_percentages():
    tools = [
        {"name": "delete_x", "description": "delete a thing"},          # write
        {"name": "fetch_x", "description": "fetch a url",
         "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},  # exfil
        {"name": "get_x", "description": "read a thing"},               # neither
        {"name": "put_x", "description": "update a thing",
         "annotations": {"destructiveHint": True}},                     # write + destructive
    ]
    ts = _label(tools)["x-mcpgawk"]["trust_surface"]
    assert ts["write_count"] == 2 and ts["write_pct"] == 50
    assert ts["exfil_count"] == 1 and ts["exfil_pct"] == 25
    assert ts["destructive_declared_count"] == 1


def test_trust_surface_empty_server_no_division_by_zero():
    ts = _label([])["x-mcpgawk"]["trust_surface"]
    assert ts == {"write_pct": 0, "exfil_pct": 0, "write_count": 0, "exfil_count": 0,
                  "destructive_declared_count": 0}


def test_annotation_completeness_matches_grade_hygiene():
    tools = [{"name": "a", "description": "x", "annotations": {"readOnlyHint": True}},
             {"name": "b", "description": "y"}]
    ac = _label(tools)["x-mcpgawk"]["annotation_completeness"]
    assert ac == {"score": 50, "annotated": 1, "total": 2}


def test_coverage_shown_in_cli_text():
    label = _label([{"name": "a", "description": "b"}],
                   prompts=[{"name": "p1"}], resources=[{"uri": "r1"}])
    out = render_cli(label)
    assert "coverage: 1 tools, 1 prompts, 1 resources" in out


def test_verbose_shows_every_tool_default_shows_only_flagged():
    # Extra unflagged reads so they don't land in top_heavy_tools (which is shown regardless
    # of verbose) and contaminate the substring check.
    tools = [{"name": "read_only", "description": "read a thing"},
             {"name": "delete_it", "description": "delete a thing"},
             {"name": "pad1", "description": "read pad"}, {"name": "pad2", "description": "read pad"},
             {"name": "pad3", "description": "read pad"}]
    label = _label(tools)
    default_bullets = [ln for ln in render_cli(label).splitlines() if ln.strip().startswith("·")]
    verbose_bullets = [ln for ln in render_cli(label, verbose=True).splitlines() if ln.strip().startswith("·")]
    assert not any("read_only" in ln for ln in default_bullets)
    assert any("delete_it" in ln for ln in default_bullets)
    assert any("read_only" in ln for ln in verbose_bullets)
    assert any("delete_it" in ln for ln in verbose_bullets)


def test_supply_chain_deprecated_renders_warning():
    label = _label([{"name": "a", "description": "b"}])
    label["x-mcpgawk"]["supply_chain"] = {
        "ecosystem": "npm", "package": "request", "version": "2.88.2",
        "deprecated": True, "detail": "request has been deprecated", "error": None,
    }
    out = render_cli(label)
    assert "DEPRECATED/YANKED" in out and "request" in out


def test_supply_chain_unrecognised_launch_renders_reason_not_silence():
    label = _label([{"name": "a", "description": "b"}])
    label["x-mcpgawk"]["supply_chain"] = {"checked": False, "reason": "package not recognised"}
    out = render_cli(label)
    assert "not recognised" in out


def test_oauth_scopes_present_vs_absent_are_distinguishable():
    label_no_flag = _label([{"name": "a", "description": "b"}])
    assert "oauth scopes" not in render_cli(label_no_flag)

    label_flag_no_token = _label([{"name": "a", "description": "b"}])
    label_flag_no_token["x-mcpgawk"]["oauth_scopes"] = None
    assert "no bearer token supplied" in render_cli(label_flag_no_token)

    label_with_scopes = _label([{"name": "a", "description": "b"}])
    label_with_scopes["x-mcpgawk"]["oauth_scopes"] = {"token_type": "jwt", "scopes": ["read", "write"]}
    assert "oauth scopes: read, write" in render_cli(label_with_scopes)
