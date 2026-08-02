#!/usr/bin/env python3
"""Open the box that leaves the building: prove a built public artefact carries no paid code.

WHY THIS EXISTS (2026-08-02). Publishing the paid engine to PyPI is unrecoverable — you cannot
unsee a wheel someone has downloaded. Everything that protected against it was source-level or
config-level: `public_sync` copies a curated list, `pyproject` names the packages, and a gate test
reads both. Nothing ever opened the built `.whl`/`.tar.gz` and looked. A packaging change, a
stray `include`, or a build backend that follows a symlink would ship paid code with every gate
still green — the same class as "test the artefact, not the sources".

WHAT IS AND IS NOT PAID. `src/gawk_platform/` is paid: enforce (the gateway), monitor, finix,
trustindex, receipt. The scanner, guard, decide and the BUNDLED VERIFY ENGINE are free and MUST
ship — an over-eager exclusion that drops `_bundled/verify` breaks the free product just as badly
as a leak, so this checks both directions.

ONE LEGITIMATE MENTION. The free CLI names `gawk_platform` inside a guarded optional import (the
licence-gated dispatcher: `from gawk_platform.cli import run_pillar`, caught and turned into
"platform unavailable"). A textual mention is therefore NOT a failure; a paid MODULE, a declared
dependency, or a missing free module IS.

Usage:
    python scripts/verify_public_artifact.py dist/mcpgawk-0.1.23-py3-none-any.whl [more...]
    python scripts/verify_public_artifact.py --build ~/devtools/mcpgawk-public

Exit codes: 0 clean · 1 a paid artefact would have shipped · 2 could not check (never treat as ok).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

#: Paid package roots. A member under any of these must never appear in a public artefact.
PAID_PREFIXES = ("gawk_platform/",)

#: Paid subsystems, checked by name as well as by package root so a re-homed module is still
#: caught (e.g. someone moves `enforce/` up a level to "simplify packaging").
PAID_MODULE_NAMES = ("trustindex", "finix", "receipt.py")

#: Free things the public package MUST contain. Over-exclusion is a failure too: a wheel with no
#: verify engine is a broken free product, and a "clean" report would be hiding that.
REQUIRED_MEMBERS = ("mcpgawk/__init__.py", "mcpgawk/discover.py", "mcpgawk/cli.py")

#: Credential shapes that must never be inside a published file. Matches are reported by PATTERN
#: and member path only — never by value, or the report becomes the leak.
SECRET_PATTERNS = (
    re.compile(rb"gawk_sk_[A-Za-z0-9_\-]{16,}"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9]{32,}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

_TEXTUAL = (".py", ".json", ".toml", ".md", ".txt", ".yaml", ".yml", ".js", ".cfg")


def _is_sdist(path: Path) -> bool:
    return path.name.endswith((".tar.gz", ".tgz"))


def _members(path: Path) -> list[str]:
    if path.suffix in (".whl", ".zip"):
        with zipfile.ZipFile(path) as z:
            return z.namelist()
    if _is_sdist(path):
        with tarfile.open(path) as t:
            return t.getnames()
    raise ValueError(f"{path.name}: not a wheel or sdist")


def _read(path: Path, member: str) -> bytes:
    if path.suffix in (".whl", ".zip"):
        with zipfile.ZipFile(path) as z:
            return z.read(member)
    with tarfile.open(path) as t:
        f = t.extractfile(member)
        return f.read() if f else b""


def _logical(path: Path, member: str) -> str:
    """An sdist nests everything under `name-version/`; compare on the path inside that."""
    if _is_sdist(path) and "/" in member:
        return member.split("/", 1)[1]
    return member


def check(path: Path) -> list[str]:
    """Every reason this artefact must not be published. Empty list means clean."""
    problems: list[str] = []
    members = _members(path)
    pairs = [(m, _logical(path, m)) for m in members]

    # 1. PAID CODE — the failure this file exists to prevent.
    for _raw, m in pairs:
        if any(m.startswith(p) or f"/{p}" in m for p in PAID_PREFIXES):
            problems.append(f"PAID MODULE in artefact: {m}")
        elif any(n in m for n in PAID_MODULE_NAMES):
            problems.append(f"PAID SUBSYSTEM in artefact: {m}")

    # 2. A DECLARED DEPENDENCY on the paid half would install it even with no file present.
    for raw, m in pairs:
        if m.endswith(("METADATA", "PKG-INFO")):
            for line in _read(path, raw).splitlines():
                low = line.lower()
                if low.startswith(b"requires-dist:") and b"gawk" in low and b"platform" in low:
                    problems.append(f"paid dependency declared: {line.decode(errors='replace')}")

    # 3. OVER-EXCLUSION is a failure too — a free product missing its own modules.
    for req in REQUIRED_MEMBERS:
        if not any(m.endswith(req) for _raw, m in pairs):
            problems.append(f"MISSING free module the public package needs: {req}")
    if not any("_bundled/verify" in m for _raw, m in pairs):
        problems.append("MISSING _bundled/verify — the verify engine is FREE and must ship")

    # 4. SECRETS. Cheap, and the one mistake with no recall path.
    #
    # VENDORED DEPENDENCIES ARE NOT SCANNED FOR SECRETS, deliberately. The first run of this gate
    # flagged `_bundled/verify/node_modules/jose/.../import.js` because the JWT library carries a
    # PEM private-key header as a PARSING CONSTANT. That is library code doing its job, not
    # a leak. A detector that cries on every crypto dependency gets switched off, and a gate people
    # switch off protects nothing (see the redactor-over-matching lesson). Vendored trees come from
    # a lockfile; the real risk is OUR OWN files carrying a credential, and those are still scanned.
    # Paid-code detection above still covers every member, vendored or not.
    # TEST FILES are skipped for the same reason: you cannot test a secret detector without
    # secret-SHAPED strings, and our suite carries fake GitHub/AWS tokens on purpose. They ship in
    # the sdist, so scanning them guarantees permanent noise. The paid-code checks above still
    # cover tests/ — an sdist shipping paid tests is caught.
    for raw, m in pairs:
        if not m.endswith(_TEXTUAL) or "node_modules/" in m or m.startswith("tests/"):
            continue
        try:
            blob = _read(path, raw)
        except Exception:                         # noqa: BLE001 — unreadable member is reported
            problems.append(f"could not read {m} to scan for secrets")
            continue
        for pat in SECRET_PATTERNS:
            if pat.search(blob):
                problems.append(f"CREDENTIAL-SHAPED STRING in {m} (pattern {pat.pattern!r})")
    return problems


def build_public(repo: Path) -> list[Path]:
    """Build sdist AND wheel from the public repo. Both are published, so both are checked."""
    out = Path(tempfile.mkdtemp(prefix="gawk-public-dist-"))
    subprocess.run([sys.executable, "-m", "build", "--outdir", str(out), str(repo)],
                   check=True, capture_output=True)
    return sorted(out.glob("*.whl")) + sorted(out.glob("*.tar.gz"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("artifacts", nargs="*", type=Path)
    ap.add_argument("--build", type=Path, metavar="PUBLIC_REPO",
                    help="build sdist+wheel from this repo and check both")
    args = ap.parse_args(argv)

    paths = list(args.artifacts)
    if args.build:
        try:
            paths += build_public(args.build)
        except subprocess.CalledProcessError as exc:
            print(f"verify-public-artifact: BUILD FAILED — cannot verify what was not built\n"
                  f"{(exc.stderr or b'').decode(errors='replace')[-2000:]}", file=sys.stderr)
            return 2
    if not paths:
        print("verify-public-artifact: nothing to check — refusing to report success",
              file=sys.stderr)
        return 2

    failed = False
    for p in paths:
        try:
            problems = check(p)
        except Exception as exc:                  # noqa: BLE001 — unknown means UNVERIFIED, not ok
            print(f"verify-public-artifact: {p.name}: COULD NOT CHECK ({exc})", file=sys.stderr)
            return 2
        if problems:
            failed = True
            print(f"verify-public-artifact: {p.name}: REFUSING TO PUBLISH", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
        else:
            print(f"verify-public-artifact: {p.name}: clean "
                  f"({len(_members(p))} members checked)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
