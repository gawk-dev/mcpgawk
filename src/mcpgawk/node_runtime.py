"""Find a Node runtime, or fetch one, so `verify` works on a machine that has never seen Node.

Why this exists: `verify` is the free flagship and it spawns `node` to run the bundled engine. A
stock macOS account has no Node at all — the 2026-08-03 acceptance run met exactly that machine.
Until now every caller did `shutil.which("node")` and, finding nothing, told the customer to go and
install Node 20+ themselves. That is a prerequisite we can meet on their behalf, so we should.

Three rules this module keeps, all of them the product's existing doctrine applied to a download:

1. **Never silently.** Fetching a runtime downloads 26 MB, unpacks to ~108 MB, and then EXECUTES it. It announces
   itself and asks, and in a non-interactive session it refuses unless explicitly told yes. Same
   shape as scan's launch consent.
2. **Pin the premise.** The version AND its SHA-256 are constants in this file, taken from
   nodejs.org's signed SHASUMS256.txt. We do not fetch a checksum from the same server that just
   handed us the bytes, because a checksum an attacker can also serve proves nothing about the
   bytes they served.
3. **A partial install is not an install.** Download and verify in a temp directory, then move into
   place atomically. A machine that loses power mid-fetch wakes up with no runtime, not with half
   of one that fails in some unrelated way three commands later.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

# Pinned deliberately. Bumping this is a decision, not a refresh: the checksums below must be
# replaced from https://nodejs.org/dist/<version>/SHASUMS256.txt in the same commit, and
# tests/test_node_runtime_pins.py asserts that every supported platform still has one.
NODE_VERSION = "v22.23.2"          # Node 22 LTS ("Jod")

# sha256 of the official .tar.xz, from nodejs.org/dist/v22.23.2/SHASUMS256.txt
_CHECKSUMS = {
    ("darwin", "arm64"): "5eff7a9011895aae3f29d06f167b84a62b028a591370c7cafb59103559fd26e1",
    ("darwin", "x64"): "96dff79f4e19a78715da559ec7cac2028f4985a175ea0c3454625a269c21deb7",
    ("linux", "arm64"): "fff4078c5def658577f92c88db7db3bc0072924bfb93fe52c1e744a54e94abb8",
    ("linux", "x64"): "d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307",
}

_DIST_BASE = "https://nodejs.org/dist"


def runtime_dir() -> Path:
    """Where a fetched runtime lives. Overridable, because a state path with no override is one
    unlucky HOME away from writing into somewhere that matters."""
    override = os.environ.get("GAWK_NODE_RUNTIME")
    return Path(override) if override else Path.home() / ".gawk" / "runtime"


def _target_triple() -> tuple[str, str] | None:
    """(os, arch) in Node's own naming, or None if nodejs.org does not ship for this machine."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(machine)
    if arch is None or system not in ("darwin", "linux"):
        return None
    return system, arch


def vendored_node() -> Path | None:
    """The runtime we fetched earlier, if it is there AND runnable. Presence is not enough: a
    truncated or half-extracted binary is a file too."""
    candidate = runtime_dir() / f"node-{NODE_VERSION}" / "bin" / "node"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate
    return None


def find_node() -> str | None:
    """Node for running the engine: the customer's own first, ours second.

    Their PATH wins deliberately. A machine that already has Node has a Node its owner chose, and
    silently preferring our copy would mean a `node --version` in their terminal disagreeing with
    the one we ran — the class of confusion that costs an afternoon to unpick.
    """
    on_path = shutil.which("node")
    if on_path is not None:
        return on_path
    ours = vendored_node()
    return str(ours) if ours is not None else None


def install_hint() -> str:
    """What to tell someone who has no Node, in one line they can act on."""
    if _target_triple() is None:
        return ("no Node runtime is available for this platform "
                f"({platform.system()} {platform.machine()}) — install Node 20+ yourself")
    return "run `mcpgawk install-node` to fetch one (26 MB download, ~108 MB on disk, no admin rights needed)"


def _download(url: str, dest: Path, *, on_progress=None) -> None:
    """Stream to disk. Streamed rather than read() because a 50 MB response held in memory on a
    machine already short of it is an avoidable way to fail."""
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https host
        total = int(response.headers.get("Content-Length") or 0)
        seen = 0
        with dest.open("wb") as handle:
            while True:
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
                seen += len(chunk)
                if on_progress is not None:
                    on_progress(seen, total)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def install_node(*, assume_yes: bool = False, quiet: bool = False) -> tuple[Path | None, str]:
    """Fetch, verify and unpack a Node runtime. Returns (path, message).

    path is None on every failure and on refusal, and the message says which — a caller must never
    have to guess whether "no path" means "declined" or "the download broke".
    """
    existing = vendored_node()
    if existing is not None:
        return existing, f"Node {NODE_VERSION} is already installed at {existing}"

    triple = _target_triple()
    if triple is None:
        return None, (f"no Node runtime is published for {platform.system()} "
                      f"{platform.machine()} — install Node 20+ yourself")
    system, arch = triple
    if (system, arch) not in _CHECKSUMS:
        # Reachable only if the pin table and _target_triple disagree. Refuse rather than fetch
        # something we cannot check: an unverified runtime is the one thing worse than no runtime.
        return None, (f"no pinned checksum for {system}-{arch} — refusing to install a runtime "
                      "we cannot verify")

    name = f"node-{NODE_VERSION}-{system}-{arch}"
    url = f"{_DIST_BASE}/{NODE_VERSION}/{name}.tar.xz"
    expected = _CHECKSUMS[(system, arch)]

    if not assume_yes:
        if not sys.stdin.isatty():
            return None, ("refusing to download a Node runtime without being asked to — this "
                          "fetches and then RUNS 26 MB of third-party code. Re-run interactively, "
                          "or pass --yes if you mean it.")
        print(f"mcpgawk needs a Node runtime to run servers and watch what they do.\n"
              f"  fetch:  {url}\n"
              f"  verify: sha256 {expected[:16]}… (pinned in mcpgawk, not fetched)\n"
              f"  into:   {runtime_dir()}  (26 MB download, ~108 MB unpacked)\n"
              f"Nothing outside that directory is touched and no admin rights are needed.")
        try:
            answer = input("Download it now? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None, "cancelled"
        if answer not in ("y", "yes"):
            return None, "declined — verify will keep falling back to declared-surface checks only"

    target_root = runtime_dir()
    target_root.mkdir(parents=True, exist_ok=True)
    final = target_root / f"node-{NODE_VERSION}"

    with tempfile.TemporaryDirectory(dir=target_root, prefix=".fetch-") as scratch:
        scratch_path = Path(scratch)
        archive = scratch_path / f"{name}.tar.xz"

        def _progress(seen: int, total: int) -> None:
            if quiet or not total:
                return
            print(f"\r  downloading… {seen / 1e6:5.1f} / {total / 1e6:.1f} MB", end="", flush=True)

        try:
            _download(url, archive, on_progress=_progress)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return None, f"download failed: {exc}"
        finally:
            if not quiet:
                print()

        actual = _sha256(archive)
        if actual != expected:
            # Loudly, and with both values: a checksum failure is either a corrupted download or
            # someone between us and nodejs.org, and the customer is entitled to know which digest
            # they actually received.
            return None, (f"CHECKSUM MISMATCH — refusing to install.\n"
                          f"  expected {expected}\n  received {actual}\n"
                          f"  from     {url}\n"
                          "Nothing was installed. If this repeats on a different network, report it.")

        member_name = f"{name}/bin/node"
        try:
            with tarfile.open(archive, "r:xz") as tar:
                try:
                    member = tar.getmember(member_name)
                except KeyError:
                    return None, f"the archive did not contain {member_name} — refusing to guess"
                if not member.isfile():
                    return None, f"{member_name} is not a regular file in the archive — refusing"
                extracted = tar.extractfile(member)
                if extracted is None:
                    return None, f"could not read {member_name} from the archive"
                staged = scratch_path / "node"
                with staged.open("wb") as handle:
                    shutil.copyfileobj(extracted, handle)
        except (tarfile.TarError, OSError) as exc:
            return None, f"could not unpack the runtime: {exc}"

        staged.chmod(staged.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        staged_root = scratch_path / "staged"
        (staged_root / "bin").mkdir(parents=True)
        staged.replace(staged_root / "bin" / "node")

        if final.exists():
            shutil.rmtree(final, ignore_errors=True)
        try:
            staged_root.replace(final)      # atomic: no half-installed runtime is ever visible
        except OSError as exc:
            return None, f"could not move the runtime into place: {exc}"

    installed = vendored_node()
    if installed is None:
        return None, "the runtime was unpacked but is not executable — refusing to claim success"
    return installed, f"Node {NODE_VERSION} installed at {installed}"
