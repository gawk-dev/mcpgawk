"""`mcpgawk login KEY` on a free install: fetch the paid engine, verify it, install it HERE.

[FOUNDER 2026-09-12] "There should not be free beta and paid path .. everything should be
seamless." Every page told a paying customer to type `mcpgawk login KEY`; on the install they
had, that exited 3 with "the Platform isn't installed" and pointed at an email. The email's
one-liner did the real work. Now `login` is that work.

The mechanism is the one that already exists and is already tested: one POST to the
token-gated endpoint with the key in the body returns a short-lived signed URL, a filename and
a sha256 (`site/api/license-status.js`, `docs/token-gated-install-plan-2026-08-22.md`). The
paid engine never ships in the public wheel — this module only ever fetches it behind a key.

THE ONE RULE FOR WHERE IT GOES: the wheel is installed where the running interpreter lives. A uv
tool environment installs with uv, a pipx venv with pipx, anything else with this interpreter's
own pip. `install.sh` chooses where the FREE package goes and keeps its fallback ladder for
that; this module does not have a ladder, because a second definition of "where mcpgawk is"
would drift from the first.

The three seams (`_post`, `_get`, `_run`) are module attributes so the tests can drive the real
entry point with the network and the installer captured. Free-engine code; syncs public.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ENDPOINT = "https://mcp.gawk.dev/api/license-status"

#: Exit codes follow cli.py's own vocabulary: 3 = cannot run (this key does not unlock the
#: engine), 4 = INCOMPLETE (ran but could not finish; 1 means findings, this is neither) — NEVER 0.
#: No failure path prints the word "installed": a customer skimming stderr must never read
#: success into a refusal. The tests pin that as a substring rule over stdout AND stderr.
EXIT_NOT_ELIGIBLE = 3
EXIT_INCOMPLETE = 4


def request_body(key: str) -> str:
    """Exactly the fields `license-status.js` reads. Pinned as data by the tests."""
    return json.dumps({"licenseKey": key, "want": "engine"})


def _post(url: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "mcpgawk-login"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:      # noqa: S310 — https, fixed host
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode() or "{}")
        except Exception:  # noqa: BLE001 — a non-JSON error page is still an error
            body = {}
        return e.code, body


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:          # noqa: S310 — the signed URL
        return resp.read()


def _run(argv: list[str], capture: bool = False) -> int:
    """Run argv. With capture=True the child's output is held and shown ONLY if it fails: the
    installer's progress chatter (uv's package list, its "not on PATH" warning) has no place
    between the two success lines of a login, but its error is exactly what a failed install must
    show. Without capture the child streams, which is what the re-exec of `login` wants."""
    if not capture:
        return subprocess.run(argv, check=False).returncode
    proc = subprocess.run(argv, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        out = ((proc.stdout or "") + (proc.stderr or "")).rstrip()
        if out:
            print(out, file=sys.stderr)
    return proc.returncode


def _download_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="mcpgawk-engine-"))


def install_argv(wheel: Path) -> list[str]:
    """The ONE rule: install where this interpreter lives."""
    prefix = Path(sys.prefix)
    uv = shutil.which("uv")
    if (prefix / "uv-receipt.toml").exists() and uv:
        return [uv, "tool", "install", "--force", str(wheel)]
    pipx = shutil.which("pipx")
    if "pipx" in prefix.parts and pipx:
        return [pipx, "install", "--force", str(wheel)]
    # A plain venv installs with its own pip — unless it has none. `uv venv` creates no pip, so
    # `uv venv && uv pip install mcpgawk` (a common path) reached here and died AFTER the engine
    # was fetched: "No module named pip" (measured on the published 0.1.52, 2026-09-22). When pip
    # is absent and uv is on PATH, let uv install into THIS interpreter — still the one rule.
    if _has_pip() is False and uv:
        return [uv, "pip", "install", "--quiet", "--python", sys.executable, "--reinstall", str(wheel)]
    return [sys.executable, "-m", "pip", "install", "--quiet", "--force-reinstall", str(wheel)]


def _has_pip() -> bool:
    """Whether `python -m pip` would run in this interpreter. Isolated so a test can decide."""
    import importlib.util
    return importlib.util.find_spec("pip") is not None


def _own_binary() -> str:
    """The `mcpgawk` this process was launched as — the one the install just replaced."""
    here = Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin") / "mcpgawk"
    if here.exists():
        return str(here)
    return shutil.which("mcpgawk") or "mcpgawk"


USAGE = (
    "usage: mcpgawk login '<license-key>'\n\n"
    "Keep the key in single quotes so your shell passes it through whole.\n\n"
    "Your key is the only thing you add. With it, `login` fetches the paid engine (pre-built,\n"
    "checksum-verified, gated on the key), installs it beside the free scanner, and saves the key\n"
    "so the paid capabilities unlock. Lost the key? It is in your subscription or trial email;\n"
    "reply to that email, or see https://mcp.gawk.dev/activate.html. The free scanner\n"
    "(`mcpgawk scan`) keeps working either way."
)


_BETA_SHAPE = re.compile(r"^gawk-beta\..+\.[0-9a-f]{32}$")   # greedy: a name may contain a dot


def looks_truncated(key: str) -> bool:
    """A beta grant ends in `.<32 hex>`. A key that lost its tail — pasted unquoted, the shell split
    an old `|`-bodied key at the first pipe; or hand-copied short — reaches `login` without a
    signature section. Caught HERE, before any network call, with the one fix named. The body is
    matched greedily because a tester's name may contain a dot (the paid verifier uses rpartition
    for the same reason)."""
    return key.startswith("gawk-beta.") and not _BETA_SHAPE.match(key)


def login_with_fetch(key: str) -> int:
    """Fetch → verify → install here → re-exec `mcpgawk login KEY` from the new binary."""
    if looks_truncated(key):
        print("mcpgawk login: that key is incomplete — a grant ends in `.<32 hex characters>` and this "
              "one does not — it was cut short in the paste. Run it again with the whole key, in single "
              "quotes:  mcpgawk login 'gawk-beta.…'", file=sys.stderr)
        return EXIT_NOT_ELIGIBLE
    print("Fetching the paid engine with your key (pre-built, checksum-verified) …", flush=True)
    status, body = _post(ENDPOINT, json.loads(request_body(key)))
    if status == 403:
        print("mcpgawk login: this key does not unlock the engine — it is not on a live trial or "
              "subscription. Subscribe at https://mcp.gawk.dev/subscribe, start a free trial at "
              "https://mcp.gawk.dev/trial.html, or check you pasted the whole key in single "
              "quotes.", file=sys.stderr)
        return EXIT_NOT_ELIGIBLE
    if status != 200 or not all(body.get(k) for k in ("url", "filename", "sha256")):
        print(f"mcpgawk login: the engine download is not available right now (HTTP {status}). "
              "Nothing changed on this machine. Try again in a minute.", file=sys.stderr)
        return EXIT_INCOMPLETE

    dest = _download_dir() / str(body["filename"]).split("/")[-1]
    try:
        data = _get(str(body["url"]))
    except Exception as e:  # noqa: BLE001 — network; say so, never pretend
        print(f"mcpgawk login: the download did not complete ({type(e).__name__}). Nothing changed "
              "on this machine. Try again in a minute.", file=sys.stderr)
        return EXIT_INCOMPLETE
    got = hashlib.sha256(data).hexdigest()
    if got != str(body["sha256"]).lower():
        print("mcpgawk login: the downloaded engine's sha256 does not match what the server "
              f"published (got {got[:16]}, want {str(body['sha256'])[:16]}). Refusing to install "
              "it. Nothing changed on this machine. Re-run; if it happens again, mail "
              "hello@nativerse-ventures.com with this line.", file=sys.stderr)
        return EXIT_INCOMPLETE
    dest.write_bytes(data)
    print(f"  ✓ engine {body.get('version', '')} fetched and checksum-verified", flush=True)

    argv = install_argv(dest)
    print(f"  installing into {sys.prefix} …", flush=True)
    rc = _run(argv, capture=True)     # quiet on success; the installer's chatter is not the login's
    try:
        dest.unlink()
    except OSError:
        pass
    if rc != 0:
        print(f"mcpgawk login: the install command exited {rc}: {' '.join(argv[:-1])} <wheel>. "
              "Nothing was activated.", file=sys.stderr)
        return EXIT_INCOMPLETE
    print("  ✓ paid engine installed", flush=True)
    # 6 — the platform's own `login` saves the key; run it from the binary that now has it.
    return _run([_own_binary(), "login", key])
