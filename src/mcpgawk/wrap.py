"""Ride the agent's own connection instead of asking for one of our own.

[FOUNDER 2026-09-08] "the claude session let us say is accessing an mcp .. then mcpgawk should get
the same level of access to do the checking .. how can we establish that .. not just with claude
but with codex and all other possible tools."

Everything mcpgawk asks of a person today exists because it stands OUTSIDE the connection: it
launches its own copy of a server (`scan`, `verify`) or signs in as itself (`login`). That is why
kite cannot be measured at all (its session is bound to the connection that asked), why Figma is a
wall, and why the gateway has to hold every backend secret.

A wrapper stands INSIDE it. The client's config launches

    mcpgawk wrap --name kite -- npx mcp-remote https://mcp.kite.trade/mcp

so the real server is started by us, in the client's own environment, with the client's own
credentials, and every byte of the session passes through:

  * `initialize` — the protocol version and the server's own name
  * `tools/list` — THE BASELINE, recorded without a scan and without a login
  * every `tools/call` — checked against that baseline as it happens

It is client-agnostic BY CONSTRUCTION: it is a config edit, not a client integration, so Claude
Code, Codex, Cursor, Windsurf, Claude Desktop, Kiro and Gemini CLI are all covered by the same
mechanism, because all of them launch servers from a file mcpgawk already reads.

THE RULES THIS FILE LIVES BY
  1. The pipe is sacred. stdout carries the protocol: nothing but the server's own bytes may ever
     be written to it. Diagnostics go to stderr.
  2. Fail open. Any error in OUR observation is swallowed and the traffic still flows. Being
     in-path means a bug here breaks the person's server, which is worse than not checking.
  3. Never record an argument. Tool arguments carry the credentials and the customer data; the
     name of the tool is what a baseline is about.
  4. Observe, in this slice. The verdict is computed and recorded as what we APPLIED — which is
     always "let it through" here. Blocking is its own slice, behind its own flag, so that
     "mcpgawk sat in the path and dropped a call" is never something that happens by surprise.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from typing import Any, BinaryIO


class Session:
    """What this connection has told us so far. Not thread-safe by luck: only the two pump threads
    touch it, one per direction, and every field is written by exactly one of them."""

    def __init__(self, name: str | None = None) -> None:
        self.config_name = name
        self.server_name: str | None = None
        self.protocol_version: str | None = None
        self.server_info: dict[str, Any] = {}
        self.tools: list[dict[str, Any]] = []
        self.pending: dict[Any, str] = {}          # request id -> method
        self.calls = 0
        self.recorded = False
        self.key: str | None = None
        self.notes: list[str] = []

    @property
    def label(self) -> str:
        return self.config_name or self.server_name or "wrapped server"


def _note(session: Session, msg: str) -> None:
    """Say it on stderr, where a client shows server logs — never on stdout, which is the wire."""
    session.notes.append(msg)
    print(f"mcpgawk wrap: {msg}", file=sys.stderr, flush=True)


def _snapshot(session: Session):
    """A ServerSnapshot built from what the WIRE said, so the recorder cannot tell the difference
    between this and a scan. Same shape in, same record out, same drift comparison."""
    from .probe import ServerSnapshot
    return ServerSnapshot(
        name=session.config_name or session.server_name or "wrapped",
        transport="stdio",
        protocol_version=session.protocol_version,
        tools=list(session.tools),
        server_info=dict(session.server_info),
        # WHAT THIS CONNECTION ACTUALLY ASKED FOR, and no more. A wrap rides the client's own
        # session and sees exactly the `tools/list` the client sent — never prompts/list or
        # resources/list, because the client had no reason to send them. Leaving this empty is
        # read downstream as "no recorded fact, do not restrict" (the right reading for records
        # written before the field existed), which made the very next full scan report the first
        # sighting of a resource as "changed since you approved it". Wrap knows better than that,
        # so it says so.
        enumerated=["tool"],
    )


def record_baseline(session: Session, *, now: str | None = None) -> str | None:
    """Record the surface this connection declared, through the ONE recorder a scan uses.

    Returns the store key, or None when nothing was recorded. This is the point of the whole
    file: a baseline that arrives because the person used their server, not because they were
    asked to do a chore.
    """
    if session.recorded or not session.tools:
        return None
    try:
        from datetime import datetime, timezone

        from . import history
        from .cli import _record_sighting          # THE recorder; never a second one
        from .measure import measure as _measure   # the package re-exports the FUNCTION under
        # this name, so `from . import measure` binds a function, not the module (cost: one
        # AttributeError swallowed by rule 2, i.e. a silently unrecorded baseline)
        sn = _snapshot(session)
        m = _measure(sn)
        stamp = now or datetime.now(timezone.utc).isoformat(timespec="seconds")
        sighting = _record_sighting(sn, m, now=stamp)
        session.recorded = True
        session.key = history.key_for(sn)
        if sighting is None:
            return None
        _note(session, f"baseline recorded for {session.label}: {len(session.tools)} tool(s), "
                       f"no scan and no sign-in needed")
        return session.key
    except Exception as exc:                       # noqa: BLE001 — rule 2
        _note(session, f"could not record the baseline ({type(exc).__name__}); traffic unaffected")
        return None


def check_call(session: Session, message: dict[str, Any]) -> None:
    """Evaluate one tools/call against the baseline and record what we APPLIED.

    Reuses `obot_filter.evaluate`, which is the same decision core the Claude Code hook uses, so a
    third adapter cannot invent a fourth opinion. In this slice we always forward, so the recorded
    decision is `allow`; a verdict that WOULD have blocked is carried in the reason, and said on
    stderr, rather than dressed up as an enforcement that did not happen.
    """
    try:
        from . import obot_filter, spool
        tool = ((message.get("params") or {}).get("name")) if isinstance(message, dict) else None
        if not isinstance(tool, str) or not tool:
            return
        session.calls += 1
        key = session.key
        name = session.config_name or session.server_name or key or "unknown"
        if not key:
            # A client may pipeline: the call can reach us before the tools/list RESPONSE that
            # gives us the baseline key. That call genuinely cannot be checked, and `defer` is
            # this vocabulary's word for "declined to check" — recording it as `allow` would
            # claim a verdict nobody computed.
            spool.record_decision(server=name, tool=tool, decision="defer", adapter="wrap",
                                  basis="declared",
                                  reason="no baseline seen yet in this session")
            return
        verdict = obot_filter.evaluate({"message": message}, server=key, record=False)
        accepted = bool(verdict.get("accept", True))
        reason = str(verdict.get("reason") or "")
        if not accepted:
            _note(session, f"WOULD BLOCK {tool}: {reason} (observing only — nothing was stopped)")
        spool.record_decision(
            server=name,
            tool=tool,
            decision="allow",                      # what we applied, always, in this slice
            adapter="wrap",
            basis="declared",
            reason=(f"would have blocked: {reason}" if not accepted else None) or None,
        )
    except Exception as exc:                       # noqa: BLE001 — rule 2
        _note(session, f"check skipped ({type(exc).__name__}); the call was forwarded")


def observe(session: Session, raw: bytes, *, from_client: bool) -> None:
    """Look at one framed message. Never raises, never blocks, never writes to stdout."""
    try:
        _observe(session, raw, from_client=from_client)
    except Exception as exc:                       # noqa: BLE001 — rule 2, and it must cover the
        # WHOLE body: the first version guarded only the JSON parse, so anything raised further in
        # (including a caller's monkeypatch) escaped into the pump thread. Caught by this file's
        # own test before it ever ran against a real server.
        _note(session, f"observation failed ({type(exc).__name__}); traffic unaffected")


def _observe(session: Session, raw: bytes, *, from_client: bool) -> None:
    try:
        msg = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, AttributeError):
        return                                     # not JSON: someone's debug line. Forward it.
    if not isinstance(msg, dict):
        return
    if from_client:
        method, mid = msg.get("method"), msg.get("id")
        if isinstance(method, str) and mid is not None:
            session.pending[mid] = method
        if method == "tools/call":
            check_call(session, msg)
        return

    # server -> client
    mid = msg.get("id")
    method = session.pending.pop(mid, None) if mid is not None else None
    result = msg.get("result")
    if not isinstance(result, dict):
        return
    if method == "initialize":
        session.protocol_version = result.get("protocolVersion") or session.protocol_version
        info = result.get("serverInfo")
        if isinstance(info, dict):
            session.server_info = info
            if isinstance(info.get("name"), str):
                session.server_name = info["name"]
    elif method == "tools/list":
        tools = result.get("tools")
        if isinstance(tools, list):
            # A paged tools/list is several responses; the baseline is all of them.
            session.tools.extend(t for t in tools if isinstance(t, dict))
            if not result.get("nextCursor"):
                record_baseline(session)


def _pump(src: BinaryIO, dst: BinaryIO, session: Session, *, from_client: bool,
          close_dst: bool = False) -> None:
    """Copy one direction, line by line, observing as it goes.

    Line-framed because that is what MCP stdio is. A message we cannot parse is still forwarded
    byte for byte — the wire is not ours to normalise.

    `close_dst` is only ever true for the client→server direction, where the child must see EOF.
    The client's stdout belongs to whoever started us and closing it is not ours to do — the first
    version closed both, which shut the stream the responses were still being written to.
    """
    try:
        for line in iter(src.readline, b""):
            # OBSERVE FIRST, THEN FORWARD. Forwarding first let the client see a tools/list
            # response and send its next call before this thread had recorded the baseline, so a
            # call that was perfectly checkable was recorded as unchecked. It is also the order a
            # blocking mode requires: a verdict after the bytes have gone is not a verdict.
            observe(session, line, from_client=from_client)
            try:
                dst.write(line)
                dst.flush()
            except (BrokenPipeError, ValueError, OSError):
                return
    except (OSError, ValueError):
        return
    finally:
        if close_dst:
            try:
                dst.close()
            except OSError:
                pass


def run(argv: list[str], *, name: str | None = None,
        stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    """Launch the real server and sit in the middle of its session. Returns its exit code."""
    if not argv:
        print("mcpgawk wrap: nothing to run — give the server's own command after `--`",
              file=sys.stderr)
        return 2
    cin = stdin if stdin is not None else sys.stdin.buffer
    cout = stdout if stdout is not None else sys.stdout.buffer
    session = Session(name=name)
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=None, env=os.environ.copy(), bufsize=0)
    except OSError as exc:
        print(f"mcpgawk wrap: could not start {argv[0]!r}: {exc}", file=sys.stderr)
        return 127
    up = threading.Thread(target=_pump, args=(cin, proc.stdin, session),
                          kwargs={"from_client": True, "close_dst": True}, daemon=True)
    down = threading.Thread(target=_pump, args=(proc.stdout, cout, session),
                            kwargs={"from_client": False}, daemon=True)
    up.start()
    down.start()
    code = proc.wait()
    down.join(timeout=2)
    if session.calls or session.tools:
        _note(session, f"session ended — {len(session.tools)} tool(s) declared, "
                       f"{session.calls} call(s) checked")
    return code


# ---------------------------------------------------------------------------------------------
# INSTALLING IT
#
# The wrapper only helps if the person's own client launches it, and every client launches from a
# config file mcpgawk already reads. So installing is a config edit — the same safe machinery the
# pin button uses, with the same proof, the same backup, and the same refusal to write anything it
# cannot verify. That is also why this works for Codex, Cursor and the rest without a line of
# per-client code.


def _mcpgawk_path() -> str:
    """The absolute mcpgawk a config file can rely on. A bare name would depend on the PATH of
    whatever launched the client, which is not the shell the person tested in."""
    import shutil
    return shutil.which("mcpgawk") or sys.executable


def install(server: str, *, undo: bool = False, dry_run: bool = False, client: str | None = None,
            home: str | None = None, log=print) -> int:
    """Point every config that names `server` at the wrapper — or take it back out.

    `client` limits it to one client's files. The founder's first real install was "claude code
    only", deliberately, so one agent runs wrapped and another runs untouched and the two can be
    compared (2026-09-08). A per-client install is the honest unit anyway: the config files belong
    to different tools with different restart costs.

    Returns a process exit code: 0 changed something, 1 nothing was changed, 2 nothing to act on.
    """
    from pathlib import Path as _Path

    from . import configedit, discover
    try:
        servers, sources = discover.discover_report(home=home) if home else discover.discover_report()
    except Exception as exc:                       # noqa: BLE001
        log(f"could not read this machine's configs: {exc}")
        return 2
    entry = (servers or {}).get(server)
    if not entry:
        log(f"{server} is not in any config on this machine")
        return 2
    if not entry.get("command"):
        log(f"{server} is a remote server — the wrapper covers stdio servers in this slice, and "
            f"an HTTP one needs the header pass-through that is not built yet")
        return 2

    root = _Path(home) if home else _Path.home()
    clients = [str(c) for c in (entry.get("_clients") or [])]
    if client:
        if client not in clients:
            log(f"{server} is not configured in {client} — it is in "
                f"{', '.join(clients) or 'no client'}")
            return 2
        clients = [client]
    paths: list[_Path] = []
    for src in sources or []:
        if src.get("client") in clients and str(src.get("status") or "").lower() == "ok":
            import glob as _glob
            paths.extend(_Path(f) for f in _glob.glob(str(root / str(src.get("path")))) [:20])
    if not paths:
        log(f"no readable config file names {server}")
        return 2

    changed = 0
    for path in paths:
        edit = (configedit.plan_unwrap(path, server) if undo
                else configedit.plan_wrap(path, server, mcpgawk=_mcpgawk_path()))
        if not edit.ok:
            log(f"  {path.name}: {edit.reason}")
            continue
        if dry_run:
            log(f"  {path.name}: would {'unwrap' if undo else 'wrap'} {server} "
                f"({len(edit.at)} entr{'y' if len(edit.at) == 1 else 'ies'})")
            changed += len(edit.at)
            continue
        res = configedit.apply_entry(edit)
        log(f"  {res.get('message')}")
        changed += int(res.get("changed") or 0)
    if not changed:
        return 1
    if not dry_run:
        log(f"restart {' and '.join(clients) or 'the client'} for it to take effect")
    return 0
