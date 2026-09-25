"""OBSERVED verification — what `wrap` watched in the client's real traffic, for servers `verify`
cannot reach.

A session-bound-auth server (the kite shape) binds its login to the one live MCP session that asked
for it. `mcpgawk verify` opens its OWN session, so it can never hold that login — it waits, times
out, and reports INCOMPLETE (measured 2026-08-27: a fresh session is "please log in first" hours
after a successful browser login). `mcpgawk wrap` sits inside the client's already-authenticated
pipe and observes the real calls, needing no login of its own. This module turns that observation
into an honest report.

THE HONESTY LINE, enforced structurally: this is OBSERVATION, never REPRODUCTION. wrap sees which
tools were declared and which were called; it never runs them in a sandbox, so it can say NOTHING
about egress, SSRF, secret leaks or output poisoning — those need verify's sandbox and are reported
as NOT TESTED, never as clean. An ObservedVerification must NEVER be written into the behaviour
profile's `verified` map (panel.py reads membership there as "verified"); it is a different, weaker
claim, and `to_dict()` is keyed `observed`, not `verified`, to make a mistake here loud.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import history, spool

#: The classes only verify's sandbox can establish. wrap watches; it does not reproduce, so every
#: one of these is untested on a wrap-observed server and must be reported as such — absence of a
#: signal here is absence of a test, not a clean bill.
NOT_TESTED: tuple[str, ...] = (
    "undeclared network egress",
    "SSRF",
    "secret leak",
    "output prompt-injection",
)


@dataclass(frozen=True)
class ObservedVerification:
    """What wrap observed for one server. `reproduced` is False by construction — this type exists
    precisely so a surface cannot accidentally present observation as reproduction."""

    server: str
    transport: str
    tools_declared: int
    tools_declared_names: tuple[str, ...]
    calls_seen: int
    tools_exercised: tuple[str, ...]
    #: Tools whose call the baseline check WOULD have denied — wrap observes only, so nothing was
    #: actually stopped; this is a pointer to look, not an enforcement that happened.
    would_block: tuple[str, ...]
    measured_at: str | None
    reproduced: bool = False
    via: str = "wrap-observation"
    not_tested: tuple[str, ...] = NOT_TESTED

    def summary_line(self) -> str:
        calls = f"{self.calls_seen} call{'s' if self.calls_seen != 1 else ''} seen in real traffic"
        return (f"OBSERVED via wrap — {self.tools_declared} tool"
                f"{'s' if self.tools_declared != 1 else ''} declared, {calls}. "
                f"This is observation, not reproduction: "
                # NO BACKTICKS. This sentence is rendered verbatim in the panel as well as the
                # terminal, and on the page the markdown-style quoting showed up as literal
                # backticks around the command (seen in the browser walk, 2026-09-17).
                f"{', '.join(self.not_tested)} were NOT tested "
                "(they need the sandbox that mcpgawk verify runs).")

    def to_dict(self) -> dict[str, Any]:
        # Deliberately keyed "observed", never "verified": a surface that renders this must show it
        # as a weaker, observed-only claim. See the module docstring's honesty line.
        return {
            "observed": True,
            "reproduced": False,
            # The honesty sentence travels WITH the dict. A surface that renders this record will
            # otherwise compose its own wording for the same fact, and the one place the limits
            # are stated becomes several places where they can drift apart.
            "summary": self.summary_line(),
            "via": self.via,
            "server": self.server,
            "transport": self.transport,
            "tools_declared": self.tools_declared,
            "tools_declared_names": list(self.tools_declared_names),
            "calls_seen": self.calls_seen,
            "tools_exercised": list(self.tools_exercised),
            "would_block": list(self.would_block),
            "measured_at": self.measured_at,
            "not_tested": list(self.not_tested),
        }


def observe(store: dict[str, Any], key: str, spool_path: str | None = None) -> ObservedVerification | None:
    """Build the observed report for one server from wrap's records, or None if wrap never saw it.

    "wrap saw it" means at least one spool decision was written by the wrap adapter for this server.
    The tool inventory comes from the baseline wrap recorded through the scan's own recorder; the
    call log comes from the decision spool. Nothing here reproduces behaviour.
    """
    servers = store.get("servers") or {}
    rec_server = servers.get(key) or {}
    hist = [r for r in (rec_server.get("history") or []) if isinstance(r, dict)]
    latest = hist[-1] if hist else {}
    _tools = latest.get("tools")
    tools = _tools if isinstance(_tools, dict) else {}
    transport = latest.get("transport") or "stdio"
    measured_at = latest.get("measured_at")

    # The spool records the server by the NAME the wrap adapter used (config name / server name /
    # key). Match against every name this key answers to, so a rename or alias does not hide traffic.
    try:
        display = history.display_name(store, key)
    except Exception:  # noqa: BLE001 — a display-name lookup must never sink the whole report
        display = key
    names = {key, display} | set(rec_server.get("aliases") or [])

    # spool.read is newest-first and caps at `limit`; the spool rotates near ~50k calls, so a high
    # cap reads the whole live file. Ordering does not matter — we count and dedupe.
    records = [d for d in spool.read(limit=100000, path=spool_path)
               if d.get("adapter") == "wrap" and d.get("server") in names]
    if not records:
        return None

    exercised = sorted({str(d.get("tool")) for d in records if d.get("tool")})
    would_block = sorted({str(d.get("tool")) for d in records
                          if isinstance(d.get("reason"), str) and "would have blocked" in d["reason"]
                          and d.get("tool")})
    return ObservedVerification(
        server=display,
        transport=transport,
        tools_declared=len(tools),
        tools_declared_names=tuple(sorted(tools)),
        calls_seen=len(records),
        tools_exercised=tuple(exercised),
        would_block=tuple(would_block),
        measured_at=measured_at,
    )
