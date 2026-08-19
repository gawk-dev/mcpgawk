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

#: TWO MODES, because one bundle cannot serve both objectives.
#:
#: The beta exists to ship a production-grade product, and that needs the COMPREHENSIVE
#: bundle: which servers, which hosts, which packages, which arguments. That is the default
#: and it is what we diagnose from.
#:
#: `strict` additionally removes identifiers — hosts, package names, command arguments — for
#: a tester whose employer will not let internal infrastructure leave the machine. It is the
#: difference between a bundle that is less useful and a bundle that is never sent.
#:
#: What is masked in BOTH modes is not a policy choice: credentials, server responses, env
#: values and the person's own name are never diagnosis in any mode.
_STRICT = False


def set_strict(strict: bool) -> None:
    """Choose the mode for this process. One-shot CLI: module state is the whole lifetime."""
    global _STRICT
    _STRICT = bool(strict)


def is_strict() -> bool:
    return _STRICT


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
    if _STRICT and parts.scheme:
        return f"<{parts.scheme}-url>"
    if parts.query:
        names = [name for name, _ in parse_qsl(parts.query, keep_blank_values=True)]
        masked = "&".join(f"{name}=<redacted>" for name in names) if names else "<redacted>"
        parts = parts._replace(query=masked)
    if parts.fragment:
        parts = parts._replace(fragment="<redacted>")
    if "@" in parts.netloc:                      # userinfo — user:password@host
        parts = parts._replace(netloc="<redacted>@" + parts.netloc.rsplit("@", 1)[1])
    return scrub_paths(urlunsplit(parts))


_ANY_URL = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*)://([^\s\"'<>,;)}\]]+)")


#: Hosts that describe OUR OWN plumbing rather than the customer's estate. A loopback
#: address says "the gateway was listening", which is diagnosis; every other host is
#: somewhere the tester's employer runs infrastructure.
_LOOPBACK = ("127.0.0.1", "localhost", "0.0.0.0", "[::1]", "::1")

#: Fields naming a network destination as a BARE host, with no scheme to spot it by. The
#: egress records that carry our best findings look like {"host": "api.example.com:443"} —
#: no `://` anywhere, so URL masking walks straight past them. Found by grepping a real
#: --strict bundle, which still named 17 hosts while the mode line promised none.
HOST_FIELDS = frozenset({"host", "hostname", "authority", "netloc", "remote_host"})

_PSEUDONYMS: dict[str, str] = {}


def reset_pseudonyms() -> None:
    _PSEUDONYMS.clear()


def pseudonym(host: str) -> str:
    """A stable stand-in per bundle, so the ANALYSIS survives strict mode.

    Blanking every host would answer "did it talk to anything" with nothing. A consistent
    label keeps what we actually reason about — how many distinct destinations there were,
    which repeated, whether one server contacted many — while naming none of them.
    """
    if any(host.startswith(loop) for loop in _LOOPBACK):
        return host
    return _PSEUDONYMS.setdefault(host, f"<host-{len(_PSEUDONYMS) + 1}>")


def _mask_host(match: re.Match) -> str:
    scheme, rest = match.group(1), match.group(2)
    host = rest.split("/")[0]
    if any(host.startswith(loop) for loop in _LOOPBACK):
        return match.group(0)
    return f"<{scheme}-url>"


def clean_text(value: str) -> str:
    """The full free-text treatment: home paths, then hosts, then credential shapes.

    Every non-loopback host is removed, not just the ones a detector calls sensitive. That
    is what lets the bundle carry a claim a security team can verify in one grep: no
    hostname of theirs appears anywhere in it. We lose our own diagnostic URLs (pypi.org in
    a currency message) — a cheap price for a file that can actually be sent.
    """
    text = scrub_paths(value)
    if _STRICT:
        text = _ANY_URL.sub(_mask_host, text)
    return redact(redact_urls_in_text(text)) or ""


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
            if _STRICT and key in HOST_FIELDS and isinstance(value, str):
                out[key] = pseudonym(value)
            elif key in TARGET_FIELDS and isinstance(value, str):
                out[key] = redact_command(value)
            elif key in CONTENT_FIELDS:
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


#: Fields carrying a server's command line or endpoint. `runlog` stores these as
#: `stdio:<the whole command>`, and on an enterprise machine that one string names the
#: internal MCP endpoint, the OAuth client id, and the private artifactory host.
TARGET_FIELDS = frozenset({"target", "command", "cmdline", "argv", "server_command"})

_PREFIXES = ("stdio:", "http:", "https:", "sse:")
#: Tokens safe to keep verbatim: subcommands, short flags, numbers. No dots, no slashes,
#: no `@`, nothing long enough to be an identifier.
_PLAIN = re.compile(r"^[A-Za-z0-9_-]{1,24}$")
_ENV_REF = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")


def _token(tok: str) -> str:
    """Classify one argv token and return it, or a label saying what it was.

    Allow-list, not deny-list: a token is kept only when it CANNOT identify anything —
    a subcommand, a flag name, a port. Everything else is labelled by kind, because the
    kind is the diagnosis (`<url>` tells us it proxies somewhere; the host does not).
    """
    if _ENV_REF.match(tok):
        return tok                                   # ${JIRA_PERSONAL_TOKEN} — a reference
    if not _STRICT:
        # Comprehensive mode: the argument is the diagnosis. Only structured blobs, which
        # are where a client id or a token hides, are collapsed.
        if tok.startswith(("{", "[")) or ('":' in tok):
            return f"<json: {len(tok)} chars>"
        # scrub_paths even here: comprehensive mode keeps the ARGUMENT, never the person.
        # A scratchpad path encodes the username as `-Users-name-`, which survived verbatim
        # until a real bundle was grepped for it.
        return scrub_paths(tok)
    if tok.startswith("-"):
        name, sep, _ = tok.partition("=")
        return f"{name}=<redacted>" if sep else name  # flag NAMES are the diagnosis
    if "://" in tok:
        return f"<{tok.split('://', 1)[0]}-url>"
    if tok.startswith(("{", "[")) or ('":' in tok):
        return f"<json: {len(tok)} chars>"
    if "@" in tok and not tok.startswith("@" ) or tok.startswith("@"):
        _, _, tag = tok.rpartition("@")
        # The VERSION is the security finding (`@latest` is unpinned); the package is not ours.
        return f"<package>@{tag}" if tag and _PLAIN.match(tag) else "<package>"
    if "/" in tok or "\\" in tok:
        return "<path-or-image>"
    if _PLAIN.match(tok):
        return tok
    return f"<arg: {len(tok)} chars>"


def redact_command(value: str) -> str:
    """Keep the SHAPE of a server command, drop everything that identifies the customer.

    A beta tester at a regulated company cannot email us their internal MCP endpoint,
    their OAuth client id or their private registry host — so a diagnostic bundle that
    carries them is a bundle that never gets sent, and the feature does not exist for
    exactly the buyers it was built for.

    What survives is what we actually diagnose from: the program, the transport, the flag
    names, whether a package is pinned, and which env vars are referenced.
    """
    prefix = ""
    body = value
    for candidate in _PREFIXES:
        if value.startswith(candidate):
            prefix, body = candidate, value[len(candidate):]
            break
    if not prefix:
        return clean_text(value)
    if "://" in body and " " not in body.strip():
        return f"{prefix}<{body.split('://', 1)[0]}-url>"
    tokens = body.split()
    if not tokens:
        return value
    program = Path(tokens[0]).name or tokens[0]
    kept = [program if _PLAIN.match(program) else "<program>"]
    kept += [_token(t) for t in tokens[1:]]
    return prefix + " ".join(kept)
