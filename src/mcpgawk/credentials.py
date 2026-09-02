"""One answer to "does this config entry point at a different account?".

Two entries can name the same binary or the same URL and still be two different servers: a work
GitHub and a personal one, billing-dev and billing-prod, two Slack workspaces. What separates them
is the LOGIN — `env` for a launched server, `headers` for a remote one.

This lives in its own leaf module on purpose. Discovery (which decides how many servers you have)
and history (which decides whose baseline a call is judged against) both need this answer, and if
they computed it separately they could disagree — one showing two servers while the other guards
them as one. `discover.py` deliberately imports nothing that pulls in the MCP SDK, so the shared
helper cannot live in `probe.py`.
"""
from __future__ import annotations

import hashlib
from typing import Any

#: Where a login can hide in an mcp.json entry. `env` carries tokens for stdio servers; `headers`
#: carries the bearer/PAT for remote ones — and the remote case is the common one for hosted
#: servers, so leaving it out would miss the motivating example (the same hosted GitHub server on
#: two accounts).
CREDENTIAL_FIELDS = ("env", "headers")

#: Set by whoever ATTACHES a credential this machine holds rather than one the config declares —
#: today `cli.with_stored_login`, which merges a stored OAuth bearer into `headers` before probing.
#: Its value is the `material()` of the entry AS DECLARED, and it wins outright.
#:
#: WHY THIS EXISTS (measured on the founder's store 2026-08-27). The fingerprint is part of the
#: store key, and this function's own contract is that it is "stable across runs by construction".
#: That holds for a credential a human writes in `mcp.json`. It broke the moment a caller began
#: injecting an OAuth ACCESS TOKEN, because that value rotates on its own: `notion` moved from
#: `dc5a20f0a98b` to `479090bf5998` on one refresh, so the next scan would have written a new key,
#: called it a first sighting, and stranded a baseline approved twenty minutes earlier. Every
#: refresh minted a new server.
#:
#: The discriminator must name the ACCOUNT, not the CREDENTIAL. A token this machine fetched says
#: nothing about which account the config points at that the config did not already say, so it
#: cannot be identity. Honoured HERE, in the one function that decides what a login IS, rather than
#: in the caller that happens to inject one — a second injector would otherwise miss the rule.
IDENTITY_AS_DECLARED = "_login_identity"


def material(entry: dict[str, Any]) -> tuple[Any, ...]:
    """The login-bearing parts of a config entry, in a stable order. Empty when it carries none.

    An entry carrying `IDENTITY_AS_DECLARED` reports what it DECLARED, never what was attached to
    it afterwards — see that constant.
    """
    if not isinstance(entry, dict):
        return ()
    if IDENTITY_AS_DECLARED in entry:
        declared = entry.get(IDENTITY_AS_DECLARED)
        return tuple(declared) if isinstance(declared, (list, tuple)) else ()
    out = []
    for field in CREDENTIAL_FIELDS:
        value = entry.get(field)
        if isinstance(value, dict) and value:
            out.append((field, tuple(sorted((str(k), str(v)) for k, v in value.items()))))
    return tuple(out)


def declared(entry: dict[str, Any], field: str) -> dict[str, str]:
    """`entry[field]` AS THE CONFIG WROTE IT — without anything mcpgawk attached afterwards.

    Config findings must be claims about the CONFIG FILE. Once `cli.with_stored_login` merges a
    stored OAuth bearer into `headers`, reading `entry["headers"]` directly reports mcpgawk's own
    token back to the user as *their* problem: `notion` was flagged "headers `Authorization` holds a
    literal credential in the config file" on 2026-08-27, and that config file contains no such
    header. An alarm that names the wrong file sends someone to fix nothing, and teaches them that
    config findings are noise.

    Falls back to the raw field when nothing was attached, so a credential a human really did write
    in `mcp.json` is reported exactly as before.
    """
    if IDENTITY_AS_DECLARED not in entry:
        value = entry.get(field)
        return dict(value) if isinstance(value, dict) else {}
    for name, items in (entry.get(IDENTITY_AS_DECLARED) or ()):
        if name == field:
            return {k: v for k, v in items}
    return {}


def fingerprint(entry: dict[str, Any]) -> str | None:
    """A short, stable digest of the login this entry uses — or None when it uses none.

    A DIGEST, never the values: this ends up in `history.json` and in the guard projection, both on
    disk, and those values are tokens. Stable across runs by construction (no salt, no time): a
    fingerprint that moved every scan would re-identify every server every run, and a drift alarm
    that always fires is one nobody reads.

    The whole of `env`/`headers` is hashed, not a guess at which keys look secret. The price is
    honest and worth saying out loud: ANY edit to them re-identifies the server and asks for
    approval once more — not only rotating a token. That direction is the safe one. Splitting one
    server into two costs a re-approval; merging two into one silently guards a server nobody
    reviewed, which is the bug this exists to close.
    """
    parts = material(entry)
    if not parts:
        return None
    return hashlib.sha256(repr(parts).encode("utf-8")).hexdigest()[:12]
