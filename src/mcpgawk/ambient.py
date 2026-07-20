"""AMBIENT CREDENTIALS — what a launched server inherits that nobody declared.

Zero egress, zero execution: this only asks whether files EXIST and what environment variables are
NAMED. It never opens a credential file, never reads a value, and never reports one. That is not
politeness — a scanner that reads your secrets to tell you they exist has become the risk it
describes.

WHY THIS EXISTS. A config entry declares what a server needs: `env: { SOME_API_KEY: ... }`, and
the report shows exactly that, values hidden. It reads like the server's credential surface. It is
not. When the server is actually launched it inherits the whole environment plus every credential
file the user can read. On a typical developer machine that includes package-registry tokens with
publish rights — so an MCP server becomes a supply-chain path into whatever that developer ships.

Two mechanisms, both real:
  * the launcher hands the child its environment (this scanner does exactly that in probe.py, and so
    does every MCP client that spawns a stdio server);
  * launchers read their own credential files — `npx -y whatever` consults ~/.npmrc regardless of
    what any MCP config says.

So the DECLARED blast radius and the ACTUAL one are different numbers, and only the smaller one was
ever reported. This module reports the gap.

It is a FACT layer: presence and name only, no judgement, no score. Whether it matters depends on
what the servers can do — which measure.py already knows — so the two are combined at the report
level, never here.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

#: Credential files a launched process can read, and what holding one lets someone do. The wording
#: is the CONSEQUENCE, not the file's name — "a token" means nothing to a reader deciding whether to
#: care, whereas "publish packages as you" does.
CREDENTIAL_FILES: list[tuple[str, str]] = [
    (".npmrc", "publish npm packages as you"),
    (".pypirc", "publish Python packages as you"),
    (".netrc", "authenticate to hosts as you"),
    (".git-credentials", "push to your git remotes"),
    (".config/gh/hosts.yml", "act on GitHub as you"),
    (".docker/config.json", "push images to your registries"),
    (".aws/credentials", "use your AWS account"),
    (".kube/config", "control your Kubernetes clusters"),
    (".ssh/id_rsa", "log in wherever that key is trusted"),
    (".ssh/id_ed25519", "log in wherever that key is trusted"),
]

#: Environment variable NAMES that look like credentials. Names only — the value is never touched.
_CREDENTIAL_NAME = re.compile(
    r"(^|_)(token|secret|password|passwd|apikey|api_key|access_key|private_key|credential)s?($|_)",
    re.IGNORECASE)


@dataclass
class AmbientExposure:
    """What a stdio server launched from here would inherit."""
    files: list[tuple[str, str]] = field(default_factory=list)   # (path shown as ~/…, consequence)
    env_names: list[str] = field(default_factory=list)           # NAMES only, never values

    @property
    def count(self) -> int:
        return len(self.files) + len(self.env_names)

    def as_dict(self) -> dict:
        return {
            "files": [{"path": p, "grants": g} for p, g in self.files],
            "env_names": list(self.env_names),
            "count": self.count,
        }


def detect_ambient(home: Path | None = None, environ: dict[str, str] | None = None) -> AmbientExposure:
    """Enumerate inheritable credential sources. Pure and injectable, so it is testable without
    touching the real home directory of whoever runs the tests."""
    home = home or Path.home()
    environ = os.environ if environ is None else environ

    files: list[tuple[str, str]] = []
    for rel, grants in CREDENTIAL_FILES:
        path = home / rel
        try:
            if path.is_file():
                files.append((f"~/{rel}", grants))
        except OSError:                      # unreadable parent, permissions — treat as absent
            continue

    # Sorted so two runs of the same machine produce the same report; an inventory that reshuffles
    # cannot be diffed, and diffing is the point.
    env_names = sorted(k for k in environ if _CREDENTIAL_NAME.search(k))
    return AmbientExposure(files=files, env_names=env_names)


def summarize(exposure: AmbientExposure, launched: int, exfil_capable: int) -> list[str]:
    """Report lines, or [] when there is nothing worth saying.

    Deliberately conditional on there being something to inherit AND something to inherit it: this
    is a property of the PAIRING. A machine full of credentials with no local servers is not a
    finding, and a local server on a machine with no credentials is not one either.

    Returns LINES, wrapped to fit a terminal. The fleet view holds an invariant that no row runs off
    an 80-column screen — a warning that wraps into unreadable soup is a warning people skip, and
    this one has to survive being read at a glance.
    """
    if not exposure.count or not launched:
        return []

    head = (f"{launched} local server{'s' if launched != 1 else ''} run as you, inheriting "
            f"credentials no MCP config declares:")
    lines = [head]

    for path, grants in exposure.files:
        lines.append(f"    {path} — {grants}")
    if exposure.env_names:
        n = len(exposure.env_names)
        lines.append(f"    {n} credential-shaped environment variable{'s' if n != 1 else ''}")
    if exfil_capable:
        lines.append(f"    {exfil_capable} of their tools can send data outward.")
    return lines
