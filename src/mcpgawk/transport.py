"""Transport permutation — never trust the declared transport.

A remote MCP server is described to us by something that is routinely wrong: a config file written
months ago, a README, or a URL the user pasted. `"transport": "sse"` on an entry that now speaks
streamable-HTTP, or a base URL whose real endpoint is `/mcp`, both produce the SAME useless outcome
today — one failed connection reported as "server down". That false UNREACHABLE is worse than no
answer: it tells the user their server is broken when it is running fine, and it hides whatever the
scan would have found.

So we do not ask what the transport *is*; we find out. Given a URL and a declared transport we build
a small ordered candidate matrix — both transports × (the path as given, the transport's
conventional path, the bare origin) — try them in order, and stop at the first one that completes an
MCP handshake. If none do, every attempt's error is aggregated into ONE honest failure instead of a
single misleading one.

The ordering is the whole design: the declared transport with the URL exactly as given is ALWAYS
candidate #1, so a correctly-configured server costs exactly one attempt and permutation adds zero
wall-clock to the happy path. Everything after #1 is a fallback that only a broken declaration pays
for.

This module is deliberately pure — no I/O, no network, no clock. Candidate generation is the part
with all the edge cases (trailing slashes, a URL that already ends in /mcp, an origin with no path,
query strings that must survive), so it is separated to be tested exhaustively on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

#: The transports we know how to speak, and the path each one conventionally lives at.
CONVENTIONAL_PATH: dict[str, str] = {"http": "/mcp", "sse": "/sse"}
TRANSPORTS: tuple[str, ...] = ("http", "sse")


@dataclass(frozen=True)
class Candidate:
    """One (transport, url) pair to try. `declared` marks the caller's original claim — candidate #1
    — which the report uses to say "you declared X, it actually answers at Y"."""
    transport: str
    url: str
    declared: bool = False

    @property
    def label(self) -> str:
        return f"{self.transport} {self.url}"


def _strip_known_suffix(path: str) -> str:
    """Reduce a path to its base by removing ONE trailing transport suffix. `/api/mcp` → `/api`,
    `/sse` → ``. Only one, and only a known one: a server legitimately mounted at `/mcp/mcp` keeps
    its parent, and a path ending in `/mcpx` is untouched."""
    p = path.rstrip("/")
    for suffix in ("/mcp", "/sse"):
        if p.endswith(suffix):
            return p[: -len(suffix)]
    return p


def _rewrite(url: str, path: str) -> str:
    """Swap the path, preserving scheme/host/port/query/fragment. A query string can carry the
    server's auth or tenant key, so dropping it would turn a working URL into a 401."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


def _paths_for(url: str, transport: str) -> list[str]:
    """Ordered, deduped candidate paths for one transport: as-given, then the transport's
    conventional path, then the bare origin (a server mounted at `/`)."""
    given = urlsplit(url).path
    base = _strip_known_suffix(given)
    # The bare origin is ALWAYS a candidate, not only when the URL ended in a known suffix. Caught
    # by the canary: for `https://host/api` the old order produced [/api, /api/mcp, /api] — so a
    # server actually mounted at `/` behind a pasted sub-path still read as "down", the exact false
    # negative permutation exists to kill.
    ordered = [given, base + CONVENTIONAL_PATH[transport], base or "/", "/"]
    # Don't try the OTHER transport's conventional path under this transport: probing `/mcp` as SSE
    # is a guess with no story behind it, and every wasted candidate is real seconds on the failure
    # path. Keeps the ladder tight now that the bare origin is always included.
    foreign = [p for t, p in CONVENTIONAL_PATH.items() if t != transport]
    if any(given.rstrip("/").endswith(f) for f in foreign):
        ordered.remove(given)
    out: list[str] = []
    for p in ordered:
        p = p or "/"
        if p not in out:
            out.append(p)
    return out


def candidates(url: str, declared: str = "http") -> list[Candidate]:
    """The ordered matrix to try for `url`.

    Candidate #1 is always the declared transport at the URL exactly as given — the happy path pays
    for nothing. Then the rest of the declared transport's paths (a wrong path is far more common
    than a wrong transport, and cheaper to be wrong about), then the other transport's paths.
    Deduped by (transport, url), so a URL already ending in `/mcp` does not get probed twice.
    """
    declared = declared if declared in CONVENTIONAL_PATH else "http"
    others = [t for t in TRANSPORTS if t != declared]

    out: list[Candidate] = []
    seen: set[tuple[str, str]] = set()
    for transport in (declared, *others):
        for path in _paths_for(url, transport):
            cand_url = url if path == urlsplit(url).path else _rewrite(url, path)
            key = (transport, cand_url)
            if key in seen:
                continue
            seen.add(key)
            out.append(Candidate(transport=transport, url=cand_url, declared=not out))
    return out
