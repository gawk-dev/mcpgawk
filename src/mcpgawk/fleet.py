"""The fleet view — one screen for every MCP server on the machine.

MCP is a fleet technology: a developer doesn't have "a server", they have seven, spread across
Claude Desktop, Cursor, VS Code and whatever they tried once and forgot. The per-server narrative
report is the right thing to read about ONE server and the wrong thing to be handed seven times in
a row — by the third screenful nobody is reading, which is the same as not scanning.

So: a compact status line per server, sorted so the ones needing you come first, and ONE batched
credential step at the end instead of an interrogation per server. The founder's rejection of
sequential prompts is the design constraint here, not an afterthought.

Pure rendering + pure state derivation. The CLI owns the I/O and the OAuth lifecycle; everything
here is a function of the labels, so the states a user sees are directly testable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ambient import detect_ambient, summarize
from .probe import _missing_program

#: The states a server can be in, in the order a human should deal with them. Ordering is a product
#: decision, not cosmetics: the things that BLOCK a scan (needs credentials, unreachable) come before
#: findings, because an unscanned server is an unknown, and an unknown outranks a known risk.
STATES = ("AUTH", "UNREACHABLE", "SKIPPED", "NOT-SCANNABLE", "REVIEW", "INCOMPLETE", "CLEAN")

_MARK = {
    "AUTH": "●", "UNREACHABLE": "●", "SKIPPED": "○", "NOT-SCANNABLE": "◌",
    "REVIEW": "●", "INCOMPLETE": "●", "CLEAN": "●",
}


@dataclass
class FleetRow:
    name: str
    state: str
    detail: str
    url: str | None = None          # set for remote servers, so the auth step knows where to go
    clients: tuple[str, ...] = ()   # which IDE / AI tool(s) this server is configured in

    @property
    def needs_auth(self) -> bool:
        return self.state == "AUTH" and bool(self.url)


def state_of(label: dict[str, Any]) -> tuple[str, str]:
    """(state, one-line detail) for a scanned server, derived from the SAME typed fields the
    per-server report uses — never by parsing its prose. A fleet view that disagreed with the
    detailed report would be worse than no fleet view."""
    x = label["x-mcpgawk"]
    n, cost = x["tool_count"], x["cost_index_tokens"]

    if x.get("is_failure"):
        if x.get("error_kind") == "auth-required":
            return "AUTH", "needs credentials — not scanned"
        if x.get("error_kind") == "misconfigured":
            return "UNREACHABLE", "config entry is not usable"
        if x.get("error_kind") == "not-an-mcp-endpoint":
            return "UNREACHABLE", "responds, but does not speak MCP"
        if x.get("error_kind") == "command-missing":
            # Deliberately NOT phrased as "dead". The entry is still configured and still approved,
            # so anything that later appears at that path is executed without being asked about
            # again. That is a standing invitation, not a dead link.
            return "UNREACHABLE", "its program no longer exists — still configured, so anything at that path would run"
        return "UNREACHABLE", "no MCP endpoint found"

    flags = x.get("risk_flags") or {}
    ts = x.get("trust_surface") or {}
    bits = [f"{n} tool{'s' if n != 1 else ''}", f"{cost:,} tok"]
    exfil, write = ts.get("exfil_count", 0), ts.get("write_count", 0)
    if exfil:
        bits.append(f"{exfil} can leak")
    elif write:
        bits.append(f"{write} can change data")

    has_dispatch = any((s.get("kind") or "").startswith("dispatch:")
                       for s in (x.get("bounded_signals") or []))
    injections = [s for s in (x.get("bounded_signals") or [])
                  if (s.get("kind") or "").startswith("injection:")]
    if injections:
        bits.append(f"⚠ {len(injections)} injection finding{'s' if len(injections) != 1 else ''}")

    detail = " · ".join(bits)
    if has_dispatch:
        return "INCOMPLETE", detail + " · hides its real catalog"
    if injections or flags.get("high_reach") or flags.get("heavy"):
        return "REVIEW", detail
    return "CLEAN", detail


def skipped_row(name: str, entry: dict[str, Any]) -> FleetRow:
    """A server we deliberately did NOT scan (consent withheld) must still be VISIBLE. Dropping it
    silently would let the fleet view imply full coverage it doesn't have — the same class of lie as
    a failed probe reading CLEAN."""
    # Show the command's BASENAME only: an absolute path to an app bundle's binary is 90 characters
    # of noise that wraps the row and tells the reader nothing they don't know.
    cmd = (entry.get("command") or "?").rsplit("/", 1)[-1]
    # Whether the program EXISTS is answerable without launching anything — it is a stat, not an
    # execution — so it is answered even here, where consent to run the server was withheld. This
    # was the whole point: a dangling entry is most likely to be found in a default scan, and
    # reporting it only when the user opts into launching would hide it exactly where it matters.
    if _missing_program(entry.get("command") or ""):
        return FleetRow(
            name=name, state="UNREACHABLE",
            detail=f"`{cmd}` no longer exists — still configured, so anything at that path would run",
            clients=tuple(entry.get("_clients") or ()))
    return FleetRow(name=name, state="SKIPPED", detail=f"local `{cmd}` — not launched (needs --yes)",
                    clients=tuple(entry.get("_clients") or ()))


def unscannable_row(item: dict[str, str]) -> FleetRow:
    """A capability that exists but that no local scan can reach. Listed, never silently omitted —
    and never offered an auth action we cannot actually perform: an account-hosted connector is
    authorised inside Claude's own UI, so a button here would be a dead end pretending to be a fix."""
    return FleetRow(name=item["name"], state="NOT-SCANNABLE", detail=item["why"],
                    clients=("claude.ai",) if item["kind"] == "account-hosted" else ("chrome",))


def build_rows(labels: list[dict[str, Any]], entries: dict[str, dict[str, Any]] | None = None,
               skipped: list[tuple[str, dict[str, Any]]] | None = None,
               unscannable: list[dict[str, str]] | None = None) -> list[FleetRow]:
    """`entries` carries the config each server came from — the auth step needs the URL and the row
    needs the client attribution; the label holds neither (it's a measurement, not a connection
    record)."""
    entries = entries or {}
    rows = []
    for lab in labels:
        state, detail = state_of(lab)
        entry = entries.get(lab["name"]) or {}
        rows.append(FleetRow(name=lab["name"], state=state, detail=detail, url=entry.get("url"),
                             clients=tuple(entry.get("_clients") or ())))
    rows += [skipped_row(n, e) for n, e in (skipped or [])]
    rows += [unscannable_row(u) for u in (unscannable or [])]
    return sort_rows(rows)


def sort_rows(rows: list[FleetRow]) -> list[FleetRow]:
    """Needs-you-first, then alphabetical. A stable, meaningful order matters more than it sounds:
    this list is read at a glance, and a fleet that reshuffles between runs cannot be scanned by eye."""
    order = {s: i for i, s in enumerate(STATES)}
    return sorted(rows, key=lambda r: (order.get(r.state, 99), r.name))


#: Section headings — the tool a developer actually recognises, not our internal client id.
_CLIENT_TITLE = {
    "claude-desktop": "CLAUDE DESKTOP",
    "claude-desktop-extension": "CLAUDE DESKTOP — extensions",
    "claude-code": "CLAUDE CODE",
    "cursor": "CURSOR",
    "vscode": "VS CODE",
    "windsurf": "WINDSURF",
    "gemini-cli": "GEMINI CLI",
    "antigravity": "ANTIGRAVITY",
    "kiro": "KIRO",
    "codex": "CODEX",
    "claude.ai": "CLAUDE.AI — account connectors (cannot be scanned)",
    "chrome": "CHROME — browser capability (not an MCP server)",
    "": "UNATTRIBUTED",
}


def _group_by_client(rows: list[FleetRow]) -> list[tuple[str, list[FleetRow]]]:
    """(client, rows) sections. A server present in several tools is listed under EACH — it really
    is configured in each, and hiding it from all but one would send the reader to the wrong config
    file when they try to remove it. Sections are ordered by their most urgent row, so the tool that
    needs attention is at the top of the screen."""
    groups: dict[str, list[FleetRow]] = {}
    for r in rows:
        for client in (r.clients or ("",)):
            groups.setdefault(client, []).append(r)
    order = {s: i for i, s in enumerate(STATES)}
    return sorted(
        ((c, sort_rows(g)) for c, g in groups.items()),
        key=lambda kv: (min(order.get(r.state, 99) for r in kv[1]), kv[0] or "zz"))


def render_fleet(rows: list[FleetRow], scanned_at: str | None = None) -> str:
    if not rows:
        return "no MCP servers found."
    # Grouped BY THE TOOL IT LIVES IN. A developer thinks "what has Cursor got?", not "give me a
    # flat list" — and to remove or change a server they have to know which tool's config to open.
    # A server configured in three tools is SCANNED once (dedup by launch identity) but LISTED under
    # each, because it is genuinely present in each.
    out = []
    for client, group in _group_by_client(rows):
        # Column width is PER SECTION: sizing it globally let one 42-character connector name
        # stretch every other section into empty space.
        width = max(len(r.name) for r in group)
        out += [f"  {_CLIENT_TITLE.get(client, client.upper())}  ({len(group)})"]
        for r in group:
            out.append(f"    {_MARK[r.state]} {r.state:<13} {r.name:<{width}}  {r.detail}")
        out.append("")

    counts = {s: sum(1 for r in rows if r.state == s) for s in STATES}
    summary = " · ".join(f"{counts[s]} {s.lower()}" for s in STATES if counts[s])
    # "16 servers" would be a lie when 6 of them are connectors and browser capabilities we can
    # never scan. Count what was actually scannable, and name the rest separately.
    scannable = len(rows) - counts["NOT-SCANNABLE"]
    head = f"  {scannable} server{'s' if scannable != 1 else ''}"
    if counts["NOT-SCANNABLE"]:
        head += f" + {counts['NOT-SCANNABLE']} beyond this machine"
    out += ["", f"{head} — {summary}"]
    if counts["NOT-SCANNABLE"]:
        # Say plainly that this part of the list is evidence-based and incomplete. These connectors
        # live in the user's Anthropic account, so one they added and never re-authorised leaves no
        # trace on disk — claiming a complete picture here would repeat the overclaim we just fixed.
        out.append("  ◌ not-scannable = runs outside this machine; listed from local traces only, "
                   "so the set may be incomplete.")

    # What every local server inherits the moment it starts, that no MCP config declares. Printed
    # in the DEFAULT view deliberately: a warning that only appears in a detail mode nobody opens
    # is the same as no warning. Counts servers that are merely CONFIGURED as well as launched ones
    # — the credentials are inherited by whatever starts them, whenever that happens.
    # A local server is one with no URL that we could in principle run: skipped, measured, or
    # dangling. NOT-SCANNABLE rows are excluded — they run in someone else's account, so they
    # inherit nothing from this machine.
    local = sum(1 for r in rows if r.url is None and r.state != "NOT-SCANNABLE")
    ambient_lines = summarize(detect_ambient(), local, 0)
    if ambient_lines:
        out.append(f"  ⚑ {ambient_lines[0]}")
        out += [f"  {ln}" for ln in ambient_lines[1:]]

    # Exactly one next step, chosen by what is actually blocking. Listing every possible flag is how
    # the old report buried the thing that mattered.
    if counts["AUTH"]:
        n_auth = counts["AUTH"]
        # Deliberately does NOT promise "authenticate below": whether a sign-in step follows depends
        # on there being a terminal, which this pure renderer cannot know. The caller prints the
        # follow-up that is actually true for the run it's in.
        out.append(f"  {n_auth} {'needs' if n_auth == 1 else 'need'} credentials before "
                   f"{'it' if n_auth == 1 else 'they'} can be scanned.")
    elif counts["SKIPPED"]:
        out.append("  Local servers were not launched. Re-run with --yes to scan them too.")
    elif counts["REVIEW"] or counts["INCOMPLETE"]:
        out.append("  Look closer at one:  mcpgawk scan --only <name> --detail")
    return "\n".join(out)


#: Bumped only on a BREAKING change to the payload below. The IDE extension pins it, so an older
#: extension talking to a newer CLI fails loudly instead of silently mis-rendering someone's fleet.
FLEET_SCHEMA = "mcpgawk.fleet/1"


def to_json(rows: list[FleetRow]) -> dict[str, Any]:
    """The fleet as DATA, for the IDE extension and any other front-end.

    The state and the one-line detail are computed HERE, in the same functions the terminal view
    uses, and shipped ready-rendered. A front-end that re-derived "is this clean?" from raw labels
    would be a second, drifting definition of the verdict — the exact class of bug the canary exists
    to prevent, except across a language boundary where no test would catch it.
    """
    counts = {s: sum(1 for r in rows if r.state == s) for s in STATES}
    return {
        "schema": FLEET_SCHEMA,
        "servers": [
            {"name": r.name, "state": r.state, "detail": r.detail, "url": r.url,
             "clients": list(r.clients), "can_authenticate": r.needs_auth}
            for r in sort_rows(rows)
        ],
        "groups": [{"client": c, "title": _CLIENT_TITLE.get(c, c.upper()),
                    "servers": [r.name for r in g]}
                   for c, g in _group_by_client(rows)],
        "summary": {
            "counts": {s: n for s, n in counts.items() if n},
            "scannable": len(rows) - counts["NOT-SCANNABLE"],
            "unscannable": counts["NOT-SCANNABLE"],
            # Carried explicitly so a front-end cannot quietly present this list as complete.
            "unscannable_may_be_incomplete": bool(counts["NOT-SCANNABLE"]),
        },
    }


def parse_auth_selection(reply: str, count: int) -> list[int]:
    """Parse the batched auth answer into 0-based indices. Accepts 'all', 'a', blank/'n' for none,
    or a list like '1,3'. Anything unparseable selects NOTHING — the same default-deny posture as
    the consent gate, because this step opens a browser and hands over a credential."""
    reply = (reply or "").strip().lower()
    if reply in ("a", "all", "y", "yes"):
        return list(range(count))
    if reply in ("", "n", "no"):
        return []
    picked = []
    for part in reply.replace(" ", ",").split(","):
        if not part:
            continue
        if not part.isdigit():
            return []                      # one bad token invalidates the whole answer
        i = int(part) - 1
        if not 0 <= i < count:
            return []
        picked.append(i)
    return sorted(set(picked))
