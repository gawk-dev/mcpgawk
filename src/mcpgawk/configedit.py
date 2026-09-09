"""Make the edit, instead of asking the person to make it.

The panel has always ended a config finding with prose: open this file, find this string, replace
it, come back and press "I fixed it". Measured 2026-09-08 on the founder's own queue: of 14 items,
5 asked for a hand edit and exactly 1 changed anything on the machine when pressed. mcpgawk knows
the file, the exact string in it and the version to write — so it can do the edit itself.

The danger is real and is why this module is separate and small: these are the founder's live
client configs, one of which (`~/.claude.json`) is written by a running Claude Code. So:

* the edit is a MINIMAL TEXT replacement — the file keeps its own formatting, key order and every
  byte we did not mean to touch (a json.dump round-trip of ~/.claude.json would rewrite megabytes
  of someone else's state);
* it is only written if the edited text re-parses EQUAL to the structure we intended. That is the
  whole safety proof: any mis-located replacement changes something else, so the comparison fails
  and nothing is written;
* the file is backed up next to itself first, and replaced atomically;
* if the file changed on disk between our read and our write, we abort and say so — a live client
  may have written it while the person was reading the item.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: the keys a client uses for its server map, in the order we look
_SERVER_MAPS = ("mcpServers", "mcp_servers", "servers", "context_servers")


@dataclass
class PinEdit:
    """One file, one server, one string to replace. Nothing is written by building this."""
    path: Path
    server: str
    before: str
    after: str
    occurrences: int = 0
    reason: str = ""
    at: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.occurrences > 0 and not self.reason


def _walk_entries(node: Any, server: str, trail: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Every path in a parsed config at which `server` is defined as an MCP server entry."""
    found: list[tuple[str, ...]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _SERVER_MAPS and isinstance(v, dict) and isinstance(v.get(server), dict):
                found.append(trail + (k, server))
            found.extend(_walk_entries(v, server, trail + (str(k),)))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(_walk_entries(v, server, trail + (str(i),)))
    return found


def _at(doc: Any, trail: tuple[str, ...]) -> Any:
    for step in trail:
        doc = doc[step] if isinstance(doc, dict) else doc[int(step)]
    return doc


def plan_pin(path: Path, server: str, before: str, after: str) -> PinEdit:
    """What pinning `server` in `path` would change — read-only, never raises.

    `before` is the spec exactly as it appears in the launch args (`mcp-remote`, or
    `gitnexus@latest`); `after` is what replaces it. An edit that cannot be located, or that would
    change anything else, comes back with a `reason` and is never applied.
    """
    edit = PinEdit(path=path, server=server, before=before, after=after)
    try:
        text = path.read_text(encoding="utf-8")
        doc = json.loads(text)
    except (OSError, ValueError) as exc:
        edit.reason = f"cannot read {path.name}: {type(exc).__name__}"
        return edit
    trails = [t for t in _walk_entries(doc, server)
              if before in (_at(doc, t).get("args") or [])]
    if not trails:
        edit.reason = f"{server} is not launched with `{before}` in {path.name}"
        return edit
    edit.at = ["/".join(t) for t in trails]
    edit.occurrences = len(trails)
    return edit


def _expected(doc: Any, server: str, before: str, after: str) -> Any:
    want = deepcopy(doc)
    for trail in _walk_entries(want, server):
        entry = _at(want, trail)
        args = entry.get("args")
        if isinstance(args, list):
            entry["args"] = [after if a == before else a for a in args]
    return want


def _retext(text: str, server: str, before: str, after: str) -> str | None:
    """The same replacement done on the TEXT, scoped to each entry that names `server`.

    Heuristic on purpose — and the caller proves it right by re-parsing. We look inside the window
    that starts at the server's own key and ends at the next server key or the end of its object,
    so a package named in a different server's args is never touched.
    """
    key = f'"{server}"'
    tok, new = f'"{before}"', f'"{after}"'
    out, i, hit = [], 0, 0
    while True:
        k = text.find(key, i)
        if k < 0:
            break
        window_end = _entry_end(text, k + len(key))
        head, body = text[i:k + len(key)], text[k + len(key):window_end]
        hit += body.count(tok)
        out.append(head + body.replace(tok, new))
        i = window_end
    if not hit:
        return None
    out.append(text[i:])
    return "".join(out)


def _entry_end(text: str, start: int) -> int:
    """End of the JSON object that follows a server key, or the end of the text."""
    depth, i, n = 0, start, len(text)
    seen = False
    while i < n:
        c = text[i]
        if c == '"':                                # skip strings, escapes and all
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c in "{[":
            depth += 1
            seen = True
        elif c in "}]":
            depth -= 1
            if seen and depth <= 0:
                return i + 1
        i += 1
    return n


def apply_pin(edit: PinEdit) -> dict[str, Any]:
    """Write the planned edit, or explain why nothing was written. Never raises.

    Returns {ok, message, backup, changed}. `changed` is the number of launch args replaced.
    """
    if not edit.ok:
        return {"ok": False, "message": edit.reason or "nothing to change", "changed": 0}
    try:
        text = edit.path.read_text(encoding="utf-8")
        doc = json.loads(text)
        stat = edit.path.stat()
    except (OSError, ValueError) as exc:
        return {"ok": False, "message": f"cannot read {edit.path.name}: {exc}", "changed": 0}

    new_text = _retext(text, edit.server, edit.before, edit.after)
    if new_text is None:
        return {"ok": False, "changed": 0,
                "message": f"`{edit.before}` is not in {edit.server}'s entry in {edit.path.name} "
                           f"any more — nothing written"}
    try:
        got = json.loads(new_text)
    except ValueError as exc:
        return {"ok": False, "changed": 0,
                "message": f"the edit would not parse ({exc}) — nothing written"}
    want = _expected(doc, edit.server, edit.before, edit.after)
    if got != want:
        return {"ok": False, "changed": 0,
                "message": f"the edit would have changed more than {edit.server}'s launch args "
                           f"in {edit.path.name} — nothing written"}
    if got == doc:
        return {"ok": True, "changed": 0, "message": f"{edit.path.name} already says "
                                                     f"`{edit.after}`"}

    backup = edit.path.with_suffix(edit.path.suffix + ".mcpgawk-backup")
    try:
        # a live client may have written the file while the person was reading the item
        if edit.path.stat().st_mtime_ns != stat.st_mtime_ns:
            return {"ok": False, "changed": 0,
                    "message": f"{edit.path.name} changed on disk just now — nothing written, "
                               f"open the item again"}
        shutil.copy2(edit.path, backup)
        fd, tmp = tempfile.mkstemp(dir=str(edit.path.parent), prefix=".mcpgawk-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(new_text)
        shutil.copystat(edit.path, tmp)
        os.replace(tmp, edit.path)
    except OSError as exc:
        return {"ok": False, "changed": 0,
                "message": f"could not write {edit.path.name}: {exc}"}
    n = sum(1 for _ in edit.at)
    return {"ok": True, "changed": n, "backup": str(backup),
            "message": f"{edit.path.name}: `{edit.before}` → `{edit.after}` "
                       f"({n} entr{'y' if n == 1 else 'ies'}); backup kept beside it"}


# ---------------------------------------------------------------------------------------------
# INSTALLING THE WRAPPER
#
# `mcpgawk wrap --name <server> -- <the server's own command>` keeps the original launch spec
# INSIDE its own arguments. That is the whole reversibility story: removing the wrapper is reading
# the original back out of the args, not restoring a backup and hoping it is current.

WRAP_ARG = "wrap"


def is_wrapped(entry: dict[str, Any]) -> bool:
    """Is this entry already launched through mcpgawk?"""
    args = entry.get("args")
    cmd = str(entry.get("command") or "")
    return (Path(cmd).name.startswith("mcpgawk") and isinstance(args, list)
            and bool(args) and args[0] == WRAP_ARG)


def wrapped_entry(entry: dict[str, Any], server: str, *, mcpgawk: str) -> dict[str, Any]:
    """The same entry, launched through mcpgawk. Everything else about it is untouched — env,
    type, cwd, and any key this version has never heard of."""
    out = dict(entry)
    original = [str(entry.get("command") or "")] + [str(a) for a in (entry.get("args") or [])]
    out["command"] = mcpgawk
    out["args"] = [WRAP_ARG, "--name", server, "--"] + original
    return out


def unwrapped_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """The original entry, read back out of the wrapper's own arguments, or None if not wrapped."""
    if not is_wrapped(entry):
        return None
    args = [str(a) for a in (entry.get("args") or [])]
    try:
        i = args.index("--")
    except ValueError:
        return None
    original = args[i + 1:]
    if not original:
        return None
    out = dict(entry)
    out["command"] = original[0]
    out["args"] = original[1:]
    return out


@dataclass
class EntryEdit:
    """One config file, one server, one whole entry replaced."""
    path: Path
    server: str
    action: str                                    # "wrap" | "unwrap"
    at: list[str] = field(default_factory=list)
    reason: str = ""
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.at) and not self.reason


def _plan_entry(path: Path, server: str, action: str,
                change) -> EntryEdit:
    edit = EntryEdit(path=path, server=server, action=action)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        edit.reason = f"cannot read {path.name}: {type(exc).__name__}"
        return edit
    trails = _walk_entries(doc, server)
    if not trails:
        edit.reason = f"{server} is not in {path.name}"
        return edit
    for trail in trails:
        entry = _at(doc, trail)
        new = change(entry)
        if new is None:
            edit.reason = (f"{server} in {path.name} is "
                           + ("already launched through mcpgawk" if action == "wrap"
                              else "not launched through mcpgawk"))
            return edit
        edit.at.append("/".join(trail))
        edit.before, edit.after = entry, new
    return edit


def plan_wrap(path: Path, server: str, *, mcpgawk: str) -> EntryEdit:
    """What launching `server` through mcpgawk would change in `path`. Read-only."""
    return _plan_entry(path, server, "wrap",
                       lambda e: None if is_wrapped(e) else wrapped_entry(e, server,
                                                                         mcpgawk=mcpgawk))


def plan_unwrap(path: Path, server: str) -> EntryEdit:
    """What removing the wrapper would restore. Read-only, and it needs no backup: the original
    command is carried in the wrapper's own arguments."""
    return _plan_entry(path, server, "unwrap", unwrapped_entry)


def apply_entry(edit: EntryEdit) -> dict[str, Any]:
    """Write a planned entry change, or explain why nothing was written. Never raises.

    Same proof as `apply_pin`: the edited TEXT must re-parse equal to the structure we intended,
    or nothing is written. The difference is scope — a whole entry object is replaced, so
    formatting INSIDE that object is normalised while every other byte of the file is untouched.
    """
    if not edit.ok:
        return {"ok": False, "message": edit.reason or "nothing to change", "changed": 0}
    try:
        text = edit.path.read_text(encoding="utf-8")
        doc = json.loads(text)
        stat = edit.path.stat()
    except (OSError, ValueError) as exc:
        return {"ok": False, "message": f"cannot read {edit.path.name}: {exc}", "changed": 0}

    want = deepcopy(doc)
    change = ((lambda e: wrapped_entry(e, edit.server, mcpgawk=str(edit.after.get("command"))))
              if edit.action == "wrap" else unwrapped_entry)
    trails = _walk_entries(want, edit.server)
    if not trails:
        return {"ok": False, "changed": 0,
                "message": f"{edit.server} is no longer in {edit.path.name} — nothing written"}
    for trail in trails:
        parent = _at(want, trail[:-1])
        new = change(_at(want, trail))
        if new is None:
            return {"ok": False, "changed": 0,
                    "message": f"{edit.server} in {edit.path.name} changed under us — "
                               f"nothing written"}
        parent[trail[-1]] = new

    new_text = _reserialise_entries(text, edit.server, want)
    if new_text is None:
        return {"ok": False, "changed": 0,
                "message": f"could not locate {edit.server}'s entry in {edit.path.name} — "
                           f"nothing written"}
    try:
        got = json.loads(new_text)
    except ValueError as exc:
        return {"ok": False, "changed": 0,
                "message": f"the edit would not parse ({exc}) — nothing written"}
    if got != want:
        return {"ok": False, "changed": 0,
                "message": f"the edit would have changed more than {edit.server}'s entry in "
                           f"{edit.path.name} — nothing written"}

    backup = edit.path.with_suffix(edit.path.suffix + ".mcpgawk-backup")
    try:
        if edit.path.stat().st_mtime_ns != stat.st_mtime_ns:
            return {"ok": False, "changed": 0,
                    "message": f"{edit.path.name} changed on disk just now — nothing written"}
        shutil.copy2(edit.path, backup)
        fd, tmp = tempfile.mkstemp(dir=str(edit.path.parent), prefix=".mcpgawk-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(new_text)
        shutil.copystat(edit.path, tmp)
        os.replace(tmp, edit.path)
    except OSError as exc:
        return {"ok": False, "changed": 0,
                "message": f"could not write {edit.path.name}: {exc}"}
    n = len(edit.at)
    verb = "now launches through mcpgawk" if edit.action == "wrap" else "launches directly again"
    return {"ok": True, "changed": n, "backup": str(backup),
            "message": f"{edit.path.name}: {edit.server} {verb} ({n} entr"
                       f"{'y' if n == 1 else 'ies'}); backup kept beside it"}


def _reserialise_entries(text: str, server: str, want: Any) -> str | None:
    """Replace each of `server`'s entry OBJECTS in the text with the intended one.

    Text-scoped like `_retext`, and proved the same way by the caller: only the object that
    follows this server's own key is rewritten, so every other byte — key order, indentation,
    comments-as-values, unrelated servers — survives.
    """
    key = f'"{server}"'
    trails = _walk_entries(want, server)
    if not trails:
        return None
    out, i, n = [], 0, 0
    while True:
        k = text.find(key, i)
        if k < 0:
            break
        after = text.find("{", k + len(key))
        if after < 0 or text[k + len(key):after].strip() not in (":", ""):
            out.append(text[i:k + len(key)])
            i = k + len(key)
            continue
        end = _entry_end(text, after)
        if n >= len(trails):
            break
        indent = " " * (k - (text.rfind("\n", 0, k) + 1))
        body = json.dumps(_at(want, trails[n]), indent=2)
        body = body.replace("\n", "\n" + indent)
        out.append(text[i:after] + body)
        i, n = end, n + 1
    if not n:
        return None
    out.append(text[i:])
    return "".join(out)
