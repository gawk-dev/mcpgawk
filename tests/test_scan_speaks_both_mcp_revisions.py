"""The scanner must reach BOTH worlds: modern (2026-07-28, `server/discover`) and legacy
(`initialize`) — during the ecosystem's upgrade wave, servers of both shapes are real.

Measured 2026-08-13 before the fix: a modern-only server (refuses `initialize`, the spec is
backward-incompatible both ways) scanned as "unreachable" — the exact wrong answer at the exact
moment the whole market upgrades. The SDK deliberately leaves discover-vs-initialize policy to the
caller. The probe tries the LEGACY handshake first — `server/discover` returns no serverInfo,
and server identity (the history key every baseline hangs off) comes from serverInfo, so a
discover-first policy silently re-identified every dual-mode server (caught by the suite). The
modern path is the FALLBACK, taken exactly when a server refuses `initialize`.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path


FIXTURES = Path(__file__).parent / "fixtures"

LEGACY_ONLY = '''
import json, sys
def send(m): sys.stdout.write(json.dumps(m)+"\\n"); sys.stdout.flush()
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: msg=json.loads(line)
    except Exception: continue
    if "id" not in msg: continue
    mid, method = msg["id"], msg.get("method")
    if method=="initialize":
        send({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":(msg.get("params") or {}).get("protocolVersion","2024-11-05"),
              "capabilities":{"tools":{}},"serverInfo":{"name":"legacy","version":"1.0"}}})
    elif method=="tools/list":
        send({"jsonrpc":"2.0","id":mid,"result":{"tools":[{"name":"old_tool","description":"legacy",
              "inputSchema":{"type":"object","properties":{}}}]}})
    elif method=="ping": send({"jsonrpc":"2.0","id":mid,"result":{}})
    else: send({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"Method not found"}})
'''


def test_a_modern_only_server_is_scanned_not_reported_unreachable():
    from mcpgawk import probe

    snap = asyncio.run(probe.probe_stdio(
        "modern", sys.executable, [str(FIXTURES / "mcp2_only_server.py")]))
    assert snap.error_kind is None, f"modern-only server unreachable: {snap.error}"
    assert snap.protocol_version == "2026-07-28"
    assert {t.get("name") for t in snap.tools} == {"modern_tool", "get_status"}


def test_a_legacy_only_server_still_scans_via_the_fallback(tmp_path: Path):
    """The other half of the policy. A probe that went modern-ONLY would break every server that
    has not upgraded — which during the wave is most of them."""
    from mcpgawk import probe

    fixture = tmp_path / "legacy_server.py"
    fixture.write_text(LEGACY_ONLY, encoding="utf-8")
    snap = asyncio.run(probe.probe_stdio("legacy", sys.executable, [str(fixture)]))
    assert snap.error_kind is None, f"legacy server unreachable: {snap.error}"
    assert snap.protocol_version == "2025-11-25", "the fallback handshake did not run"
    assert [t.get("name") for t in snap.tools] == ["old_tool"]


def test_the_recorded_protocol_version_distinguishes_the_worlds():
    """Drift's raw material: 'this server now answers a different revision' is exactly the
    upgrade-audit signal, so the snapshot must record which world it spoke."""
    from mcpgawk import probe

    modern = asyncio.run(probe.probe_stdio(
        "m", sys.executable, [str(FIXTURES / "mcp2_only_server.py")]))
    assert modern.protocol_version == "2026-07-28"


def test_verify_behaviourally_checks_a_modern_only_server(tmp_path: Path):
    """The other half of dual-protocol support, through the SHIPPED engine: a 2026-07-28-only
    server is not merely listed but behaviourally VERIFIED — tools called in the sandbox, checks
    completed, coverage claimed. Before the engine grew its own modern client (the official TS SDK
    has no v2 — checked npm dist-tags 2026-08-13), this exact run reported "no server was verified
    at all"."""
    import json
    import subprocess

    from mcpgawk import verify as verify_mod

    if verify_mod.unavailable_reason() is not None:
        pytest.skip("verify unavailable here")
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"srv": {
        "command": sys.executable, "args": [str(FIXTURES / "mcp2_only_server.py")]}}}),
        encoding="utf-8")
    out = tmp_path / "report.json"
    subprocess.run([sys.executable, "-m", "mcpgawk.cli", "verify", str(cfg), "--out", str(out)],
                   capture_output=True, text=True, timeout=300,
                   cwd=str(Path(__file__).parent.parent))
    assert out.is_file(), "no report written — vacuous"
    srv = json.loads(out.read_text(encoding="utf-8"))["servers"][0]
    assert srv["complete"] is True, f"verify did not complete against a modern-only server: {srv}"
    assert srv["toolsChecked"] >= 1, "no tool was exercised — the modern path carried no calls"
    assert srv["status"] == "clean", srv["status"]
