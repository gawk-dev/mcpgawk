"""CONSENT — default-deny before LAUNCHING a local (stdio) MCP server.

Spawning a stdio server RUNS its code on your machine. Zero-config `mcpgawk scan` discovers servers
across your IDE configs and would otherwise launch every one of them silently — so when servers come
from discovery or a config file (NOT a command you just typed), gawk enumerates the launch plan,
redacts env values, and asks before launching, defaulting to NO.

Explicit `mcpgawk scan --stdio "<cmd>"` is your own typed command — implicit consent, never prompted
(that path never reaches this gate). Remote (http/sse) servers are connected to, not spawned, so they
run no local code and are never gated here.

The plan and prompt go to STDERR so `--json` stdout stays clean; the reply is read from stdin.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Callable

Target = tuple[str, dict[str, Any]]


#: Set by the front door once the user has answered the launch question, so the scan underneath
#: does not ask it a second time. Never a way to SKIP consent — it is only honoured together with
#: an explicit yes, and the front door sets it only after a real answer.
CONSENT_GIVEN_ENV = "MCPGAWK_CONSENT_GIVEN"


def _format(name: str, entry: dict[str, Any]) -> str:
    cmd = str(entry.get("command", ""))
    args = entry.get("args") or []
    line = f"    • {name}: {cmd} {' '.join(map(str, args))}".rstrip()
    env = entry.get("env") or {}
    if isinstance(env, dict) and env:
        # Show which env vars are passed, NEVER their values (they carry the secrets).
        line += f"\n        env: {', '.join(sorted(env))}  (values hidden)"
    return line


def gate_stdio_consent(
    targets: list[Target],
    *,
    assume_yes: bool = False,
    stdin_isatty: bool | None = None,
    ask: Callable[[], str] = input,
    err=None,
) -> list[Target]:
    """Return the subset of `targets` approved to scan. Remote servers always pass (no code runs);
    local (stdio) servers are launched only with consent — `--yes` (assume_yes), an interactive 'y',
    and never by default. Non-interactive without `--yes` fails closed: remote-only.

    Injectable (`ask`/`err`/`stdin_isatty`) so it's testable without a real TTY."""
    stdio = [(n, e) for n, e in targets if e.get("command")]
    remote = [(n, e) for n, e in targets if not e.get("command")]
    if not stdio:
        return list(targets)  # nothing to spawn — no consent needed

    err = sys.stderr if err is None else err  # resolved at CALL time (so capsys/redirection works)
    # ALREADY ASKED. The front door (`mcpgawk`) puts this exact question to the user, with fuller
    # disclosure, and remembers the answer. Re-announcing here made a first run ask, get an answer,
    # and then immediately restate the warning — which reads as though the answer was ignored and
    # quietly undermines the "asked once" promise the prompt makes.
    if os.environ.get(CONSENT_GIVEN_ENV) == "1" and assume_yes:
        return list(targets)
    isatty = sys.stdin.isatty() if stdin_isatty is None else stdin_isatty
    n = len(stdio)
    print(f"\n⚠  {n} local server{'s' if n != 1 else ''} would be LAUNCHED to scan "
          f"— this RUNS their code on your machine:", file=err)
    for name, entry in stdio:
        print(_format(name, entry), file=err)

    if assume_yes:
        print("→ launching (--yes given).", file=err)
        return list(targets)

    if not isatty:
        print(f"→ NOT launched: default-deny in a non-interactive run. Re-run with --yes to launch "
              f"them, or in a terminal to approve. Scanning {len(remote)} remote server(s) only.",
              file=err)
        return remote

    err.write(f"Launch {'these' if n != 1 else 'this'} {n} local server{'s' if n != 1 else ''}? [y/N] ")
    err.flush()
    reply = (ask() or "").strip().lower()
    if reply in ("y", "yes"):
        return list(targets)
    print(f"→ skipped. Scanning {len(remote)} remote server(s) only.", file=err)
    return remote
