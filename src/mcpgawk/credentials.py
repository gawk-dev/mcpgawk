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


def material(entry: dict[str, Any]) -> tuple[Any, ...]:
    """The login-bearing parts of a config entry, in a stable order. Empty when it carries none."""
    if not isinstance(entry, dict):
        return ()
    out = []
    for field in CREDENTIAL_FIELDS:
        value = entry.get(field)
        if isinstance(value, dict) and value:
            out.append((field, tuple(sorted((str(k), str(v)) for k, v in value.items()))))
    return tuple(out)


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
