"""Config-only findings: what a server's launch configuration says before anything runs.

WHY THIS LAYER EXISTS (beta tester 1, 2026-08-19). Her non-interactive first scan declined to
launch every local server — correctly: launching runs their code — and so the product said
nothing at all. "Findings 0" because nothing was scanned, not because nothing was wrong. Her
config alone showed TLS verification disabled on a credential-bearing server, both IDE servers
on an unpinned `@latest` (the postmark-mcp shape: fifteen clean versions, then v1.0.16
exfiltrated mail), and `--allow-build` letting install scripts run. This module reads ONLY the
entry dict the scan already holds — zero execution, zero egress — so it answers on exactly the
locked-down machines whose owners will not launch anything, and it answers for DECLINED servers,
where the need is greatest.

LAYER RULES:
- Pure function of the config entry. No subprocess, no network, no filesystem access.
- Exactly the four detectors the tester's evidence named. A fifth needs its own recorded case.
- Evidence names the KEY, never the value: a finding that prints the credential ships it into
  every `checkup`/`report` bundle. No URLs or hosts in evidence either — that would reintroduce
  the strict-mode host-pseudonymisation hole fixed in 0.1.31 through a new door.
- These are NOT bounded language signals. signals.py is model-facing text only (enforced by
  test_layer_invariants); findings from here merely RIDE the `bounded_signals` list as a carrier,
  because every renderer keyed on the kind prefix then carries them unchanged. `confidence` says
  "config", not "signal": these are deterministic facts about a file, not heuristics.
- Detection is not redaction. redact.py deliberately over-matches (64/64 false positives when it
  was tried as a detector — on file); the credential test here is signals._credential_line, the
  0-FP-disciplined one, with placeholder/indirection/path guards IN FRONT of it.
- The scan exit code is deliberately unchanged: config findings inform, they do not fail CI.
  Flipping exits on a class this common (unpinned is the ecosystem default) would train people
  to --no-signals, which silences the findings that DO warrant it.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .ambient import _CREDENTIAL_NAME
from .signals import Finding, _credential_line
from .supplychain import _split_npm_spec, extract_package

#: Registry of every kind this module may emit — the canary test walks it both ways (every kind
#: literal below is registered; every registered kind has a firing fixture).
CONFIG_KINDS: dict[str, str] = {
    "config:unpinned-package": "package version floats — every launch installs whatever upstream publishes next",
    "config:tls-off": "NODE_TLS_REJECT_UNAUTHORIZED=0 — TLS certificate verification disabled",
    "config:install-scripts": "--allow-build lets the package's install scripts run at launch",
    "config:plaintext-credential": "a literal credential stored in the config file",
}

#: Short names for one-line surfaces (fleet row detail). Keyed by kind, must cover CONFIG_KINDS.
SHORT: dict[str, str] = {
    "config:unpinned-package": "unpinned version",
    "config:tls-off": "TLS verification off",
    "config:install-scripts": "install scripts allowed",
    "config:plaintext-credential": "plaintext credential",
}

#: Kinds serious enough to move a fleet row to REVIEW on their own. Unpinned/install-scripts stay
#: informational: unpinned is the ecosystem's README default, and a fleet view that flags every
#: row teaches the reader to stop looking (the redactor-over-matching lesson, applied to states).
RISKY_KINDS = frozenset({"config:tls-off", "config:plaintext-credential"})


def _unpinned_package(name: str, entry: dict[str, Any]) -> list[Finding]:
    command = entry.get("command") or ""
    if not command:
        return []                                   # remote servers have no launch spec
    pkg = extract_package(command, entry.get("args") or [])
    if not pkg:
        return []                                   # bare local binary — supplychain's own rule: skip, never guess
    eco, spec = pkg
    if eco == "npm":
        _, pin = _split_npm_spec(spec)
        floating = pin is None or pin in ("latest", "*", "")
    else:  # pypi — uvx/pipx accept PEP 508 `pkg==1.2.3` and uv's `pkg@1.2.3`
        _, _, tag = spec.partition("@")
        floating = "==" not in spec and (not tag or tag == "latest")
    if not floating:
        return []
    return [Finding(
        tool=name, kind="config:unpinned-package", confidence="config",
        evidence=f"`{spec}` has no version pin — every launch installs whatever upstream "
                 f"publishes next (postmark-mcp shipped 15 clean versions, then v1.0.16 "
                 f"exfiltrated mail)")]


def _tls_off(name: str, entry: dict[str, Any]) -> list[Finding]:
    env = _declared(entry, "env")
    # A finding ONLY when the value is exactly "0" — "1" is someone turning verification back ON.
    if str(env.get("NODE_TLS_REJECT_UNAUTHORIZED", "")).strip() != "0":
        return []
    evidence = ("NODE_TLS_REJECT_UNAUTHORIZED=0 — certificate verification is off for every "
                "request this server makes")
    if any(k != "NODE_TLS_REJECT_UNAUTHORIZED" and _CREDENTIAL_NAME.search(k) for k in env):
        evidence += "; this config also carries credentials, which now travel unverified"
    return [Finding(tool=name, kind="config:tls-off", confidence="config", evidence=evidence)]


def _install_scripts(name: str, entry: dict[str, Any]) -> list[Finding]:
    if "--allow-build" not in (entry.get("args") or []):
        return []
    return [Finding(
        tool=name, kind="config:install-scripts", confidence="config",
        evidence="`--allow-build` — the package's install scripts run with your permissions at "
                 "every launch")]


#: Values that are config INDIRECTION, not a stored literal: `${VAR}` / `$VAR` expansion and
#: secret-manager references. Pointing at a credential is the right pattern — never a finding.
_INDIRECTION_PREFIXES = ("$", "op://", "keychain:", "secretmanager:", "vault:")

#: Auth-scheme headers whose NAME does not look credential-ish to the assignment test. The scheme
#: word is stripped so the MATERIAL is tested: `Authorization: Bearer <literal>` is a stored
#: credential exactly as much as `GITHUB_TOKEN=<literal>`.
_AUTH_HEADERS = frozenset({"authorization", "proxy-authorization"})

from .credentials import declared as _declared  # noqa: E402 — beside the detectors that use it
_SCHEME_RX = re.compile(r"(?i)^(bearer|basic|token)\s+")


def _plaintext_credentials(name: str, entry: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for field in ("env", "headers"):
        # What the CONFIG declares, never what mcpgawk attached to it — see credentials.declared.
        for key, raw in _declared(entry, field).items():
            if not isinstance(raw, str):
                continue
            value = raw.strip()
            if not value or value.startswith(_INDIRECTION_PREFIXES):
                continue
            if value.startswith(("/", "~", "./")):
                continue                             # a PATH to a credential is the right pattern
            if field == "headers" and key.lower() in _AUTH_HEADERS:
                probe_line = f"token={_SCHEME_RX.sub('', value)}"
            else:
                probe_line = f"{key}={value}"
            # signals._credential_line: placeholder guard, then vendor-shaped literals, then the
            # 0-FP-tuned assignment test (never redact.py's any-8-chars redactor patterns).
            if _credential_line(probe_line):
                out.append(Finding(
                    tool=name, kind="config:plaintext-credential", confidence="config",
                    evidence=f"{field} `{key}` holds a literal credential in the config file "
                             f"(value not shown)"))
    return out


_DETECTORS = (_unpinned_package, _tls_off, _install_scripts, _plaintext_credentials)


def check(name: str, entry: dict[str, Any]) -> list[Finding]:
    """Every config-only finding for one server entry. Pure; safe to call on ANY entry — probed,
    declined, remote — because it only ever reads the dict."""
    findings: list[Finding] = []
    for detect in _DETECTORS:
        findings.extend(detect(name, entry))
    return findings


def summarize(findings: list[Finding]) -> str:
    """One short clause for single-line surfaces (fleet row detail). Empty string when clean."""
    if not findings:
        return ""
    counts = Counter(f.kind for f in findings)
    parts = []
    for kind, n in counts.items():
        label = SHORT.get(kind, kind)
        parts.append(f"{n}× {label}" if n > 1 else label)
    return "⚠ config: " + ", ".join(parts)
