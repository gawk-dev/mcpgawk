"""Structural redaction for `mcpgawk report`.

`redact.py` already masks credential and PII SHAPES wherever they appear, and this module
does not repeat that work — it calls it. What it adds is the layer above:

  * **structural** redaction — some fields are the tester's data by definition
    (`resultTextExcerpt` is whatever their MCP server returned: their trades, their notes,
    their mail). We drop those by FIELD NAME, whatever the value looks like. A detector
    that misses one leaks a stranger's data into our inbox and nobody ever finds out;
    dropping by name cannot under-match.
  * **home-path scrubbing** — `/Users/<their name>/…` appears in almost every stack trace
    we collect and is personal data. Nothing in the codebase removed it before this.

Every redaction announces itself in place (`<redacted: 412 chars>`), never blanks the
field, so a reader can tell "this was empty" from "this was removed" — the same three-state
rule the rest of the product follows.
"""

from __future__ import annotations

import getpass
import json
import platform
import socket
from pathlib import Path
from typing import Any
import re

from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .redact import redact, redact_urls_in_text

#: Fields whose VALUE is the tester's own data by definition. Verified against the record
#: shapes we actually ship (verify `audit.jsonl`, the call spool), not guessed:
#: `resultTextExcerpt` carries raw MCP server output on 4214 of 4513 records in a real run.
CONTENT_FIELDS = frozenset({
    "resultTextExcerpt", "result", "content", "text", "output", "response", "body",
    "arguments", "args", "params", "input", "prompt", "message",
})

#: URL-shaped fields. NOTE: `redact.redact_url` is deliberately NOT used on these. It masks
#: only SECRET-NAMED parameters, and an OAuth callback leaks through it — `code=` and
#: `state=` are live credentials with innocuous names. Caught by this module's own test.
#: Here we keep scheme, host, path and every parameter NAME, and mask every VALUE.
URL_FIELDS = frozenset({"url", "uri", "endpoint", "redirect_uri", "callback"})

_HOME = re.compile(r"/(?:Users|home)/[^/\s\"']+")
_WINHOME = re.compile(r"([A-Za-z]:\\{1,2})Users\\{1,2}[^\\\s\"']+")


def _identity_terms() -> list[str]:
    """The literal strings that identify this human, longest first.

    A path regex is not enough. The username reaches the bundle in shapes that are not
    paths at all — a scratchpad directory encodes `/Users/name/x` as `-Users-name-x`, and a
    machine name is often a person's name outright ("Susha's MacBook"). So we also strike
    the literals wherever they appear, in any encoding.

    Terms shorter than four characters are skipped: a username like `dev` or `ana` would
    match inside ordinary words and shred the diagnosis to protect nothing the path scrub
    has not already handled.
    """
    terms: set[str] = set()
    for getter in (getpass.getuser, platform.node, socket.gethostname,
                   lambda: Path.home().name):
        try:
            value = (getter() or "").strip()
        except Exception:                                        # noqa: BLE001 — best effort
            continue
        if len(value) >= 4:
            terms.add(value)
            if "." in value:                                     # host.local -> host
                head = value.split(".")[0]
                if len(head) >= 4:
                    terms.add(head)
    return sorted(terms, key=len, reverse=True)


def scrub_paths(text: str) -> str:
    """Remove anything that identifies the machine or the person using it.

    Home directories become `~`; the username and machine name become `<user>` and `<host>`
    wherever they appear, path-shaped or not.
    """
    text = _WINHOME.sub(r"~\\", _HOME.sub("~", text))
    user_terms = {Path.home().name, _safe(getpass.getuser)}
    for term in _identity_terms():
        text = text.replace(term, "<user>" if term in user_terms else "<host>")
    return text


def _safe(getter) -> str:
    try:
        return (getter() or "").strip()
    except Exception:                                            # noqa: BLE001
        return ""


def redact_query_values(url: str) -> str:
    """Keep scheme://host/path and the parameter NAMES; mask every parameter VALUE.

    Stronger than `redact.redact_url`, on purpose. That function masks parameters whose NAME
    looks secret, which is right for a finding rendered to the operator's own screen — but an
    OAuth callback (`?code=…&state=…`) carries live credentials under innocuous names, and
    this bundle leaves the tester's machine. Knowing a `code` parameter was present is the
    diagnosis; its value never is.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<redacted: unparseable url>"
    if parts.query:
        names = [name for name, _ in parse_qsl(parts.query, keep_blank_values=True)]
        masked = "&".join(f"{name}=<redacted>" for name in names) if names else "<redacted>"
        parts = parts._replace(query=masked)
    if parts.fragment:
        parts = parts._replace(fragment="<redacted>")
    if "@" in parts.netloc:                      # userinfo — user:password@host
        parts = parts._replace(netloc="<redacted>@" + parts.netloc.rsplit("@", 1)[1])
    return scrub_paths(urlunsplit(parts))


def clean_text(value: str) -> str:
    """The full free-text treatment: home paths, then URLs, then credential shapes.

    Order matters and mirrors `runlog._mask`: URLs are masked before the generic pass, so a
    credential inside a query string is caught as a URL parameter rather than mangled first.
    """
    return redact(redact_urls_in_text(scrub_paths(value))) or ""


def announce(value: Any) -> str:
    """Say what was removed, and how big it was, so the shape stays legible."""
    if isinstance(value, str):
        return f"<redacted: {len(value)} chars>"
    if isinstance(value, (list, tuple)):
        return f"<redacted: {len(value)} item(s)>"
    if isinstance(value, dict):
        return f"<redacted: {len(value)} key(s)>"
    return "<redacted>"


def redact_record(record: Any) -> Any:
    """Redact one decoded JSON record, recursively, by field NAME.

    Keys are always kept: that a call carried an `api_key` argument is the diagnosis;
    its value is the leak.
    """
    if isinstance(record, dict):
        out: dict[str, Any] = {}
        for key, value in record.items():
            if key in CONTENT_FIELDS:
                out[key] = announce(value)
            elif key in URL_FIELDS and isinstance(value, str):
                out[key] = redact_query_values(value)
            elif isinstance(value, (dict, list)):
                out[key] = redact_record(value)
            elif isinstance(value, str):
                out[key] = clean_text(value)
            else:
                out[key] = value
        return out
    if isinstance(record, list):
        return [redact_record(item) for item in record]
    if isinstance(record, str):
        return clean_text(record)
    return record


def redact_jsonl(path: Path) -> tuple[str, int, int]:
    """Redact a whole .jsonl file. Returns (text, records, undecodable).

    A line we cannot decode is NOT passed through raw — we cannot redact what we cannot
    parse — so it is replaced and COUNTED, and the count reaches the manifest. Dropping it
    silently would let the bundle read as complete when it was not.
    """
    lines: list[str] = []
    records = 0
    undecodable = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            try:
                decoded = json.loads(raw)
            except (ValueError, TypeError):
                undecodable += 1
                lines.append(json.dumps({"_unparseable_line": announce(raw)}))
                continue
            records += 1
            lines.append(json.dumps(redact_record(decoded), separators=(",", ":")))
    return ("\n".join(lines) + "\n" if lines else ""), records, undecodable
