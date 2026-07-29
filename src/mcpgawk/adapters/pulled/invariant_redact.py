# Portions adapted from Invariant Labs / Snyk agent-scan (Apache-2.0, © 2025 Invariant Labs AG),
#   github.com/invariantlabs-ai/mcp-scan (now snyk/agent-scan)
#   @ 74ad3eaa018521d3aec5ae6599e13462000dbfa6 (src/agent_scan/redact.py, `redact_absolute_paths`).
#   Modified by the gawk platform: ported verbatim, unchanged algorithm — this function has been
#   byte-identical across every version of the upstream project checked (from its original
#   mcp_scan module name through the Agent Scan rebrand). No cloud-egress paths existed in this
#   function to remove. See THIRD_PARTY_LICENSES.md.
#
#   `redact_command_args` below is NOT ported — see its own docstring: the upstream project's
#   current `redact_args` depends on the `detect-secrets` library (format/entropy/keyword
#   detectors), which the gawk platform deliberately doesn't add as a dependency (same call as
#   skipping the ML-based PII/prompt-injection detectors elsewhere in the extraction inventory —
#   real operational cost for a product that wants to stay dependency-light). It reimplements the
#   SAME CONCEPT (redact CLI flag values, since a launch command's argv often carries secrets as
#   plain arguments) with gawk's own flag/value heuristic instead.
# SPDX-License-Identifier: Apache-2.0
"""Redaction for evidence that crosses the sandbox boundary — reproduction commands and captured
process output. Before this module existed, `sandbox.py`'s `Evidence.reproduction_command` and
`Evidence.output_excerpt` had ZERO redaction: a launch command with a secret passed as a CLI flag
value, or a crash traceback containing an absolute filesystem path, flowed straight into the
returned/persisted `VerifiedFinding` unscrubbed. `enforce/gateway.py`'s live per-call path already
redacted; Verify's evidence path did not — this closes that asymmetry.
"""
from __future__ import annotations

import re

REDACTED = "**REDACTED**"


def redact_absolute_paths(text: str | None) -> str | None:
    """Redact absolute file paths (Unix, Windows, `~/`) in a string, preserving structure."""
    if not text:
        return text
    patterns = [
        r'/(?:[^/\s"\'<>|:]+/)+[^/\s"\'<>|:]*',
        r'~/[^\s"\'<>|:]+',
        r'[A-Za-z]:[/\\](?:[^/\\\s"\'<>|:]+[/\\])*[^/\\\s"\'<>|:]*',
    ]
    result = text
    for pattern in patterns:
        result = re.sub(pattern, REDACTED, result)
    return result


def _is_path(arg: str) -> bool:
    if arg.startswith("/") and len(arg) > 1:
        return True
    if arg.startswith("~/"):
        return True
    return len(arg) >= 3 and arg[1] == ":" and arg[2] in "/\\"


def redact_command_args(args: list[str]) -> list[str]:
    """Redact values of flag-style arguments and bare filesystem paths — ours, reimplemented
    fresh (see module docstring for why the upstream `detect-secrets`-based version wasn't
    ported). Same shape as upstream's simpler predecessor: a launch command's flags
    (`--api-key`, `-k`) commonly carry secrets as their next positional value; paths are
    filesystem structure, not identity, and gawk's redaction goal here is "don't let a
    reproduction command leak a credential or a machine's directory layout," not full
    entropy-based secret detection (that's `enforce/gateway.py`'s job, on tool OUTPUT)."""
    if not args:
        return args
    redacted: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-") and "=" in arg:
            eq_idx = arg.index("=")
            redacted.append(arg[: eq_idx + 1] + REDACTED)
            i += 1
        elif arg.startswith("-") and arg not in ("-y", "--yes"):
            redacted.append(arg)
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                redacted.append(REDACTED)
                i += 2
            else:
                i += 1
        elif _is_path(arg):
            redacted.append(REDACTED)
            i += 1
        else:
            redacted.append(arg)
            i += 1
    return redacted
