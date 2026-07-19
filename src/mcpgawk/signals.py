"""BOUND / BOUNDED layer — heuristic risk *signals*, kept physically apart from measure.py.

The wall: this module has NO token math and NO capability facts; measure.py has NO signals.
An estimate can therefore never contaminate a fact.

0-FP discipline (authdrift lesson): every detector here is deliberately *precise* — it fires only
on language aimed at the reader/model, never on legitimate tool capability keywords (a `url` param
or a `delete` verb is a FACT, handled in measure.py, not a signal here). A detector ships only after
a measured 0 false positives on a real clean corpus (see tests/test_signals.py + the live FP gate).

A signal is a SIGNAL, never a verdict. We never say "server X is insecure".
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .probe import ServerSnapshot

# THE catalog of every bounded-signal `kind` this module can emit, mapped to the detector that
# emits it. Single source of truth for the anti-drift canary (tests/test_canary_signals.py), which
# fails the build if:
#   * a detector emits a `kind` literal not registered here (static scan of this file's source);
#   * a registered kind has no live fixture proving its detector actually fires it;
#   * a kind's family (the part before ':') has no label lead phrase (label._SIGNAL_LEAD), i.e. it
#     could be mislabelled in the report.
# Adding a detector without registering + fixture-testing + labelling its kind cannot pass CI. This
# is the mechanism that ends fix-on-the-go: scan coverage and report correctness cannot silently rot.
# (Discovery scopes will register the same way here once discovery lands — roadmap SCAN/Discovery.)
SIGNAL_KINDS: dict[str, str] = {
    "injection:hidden-markup": "detect",
    "injection:reader-directed": "detect",
    "injection:secret-exfil": "detect",
    "dispatch:dynamic-tool-catalog": "detect_dynamic_dispatch",
    "shadowing:name-collision": "detect_shadowing",
    "servercard:undeclared-tools": "detect_card_mismatch",
}

# --- Detector 1: hidden markup in a description (HTML comments / pseudo-system tags). ---
# Legit tool descriptions are plain prose; an embedded comment or <important>/<system> tag is
# the classic tool-poisoning carrier (Invariant's own local rule keyed on <IMPORTANT>).
_HIDDEN_MARKUP = re.compile(r"<!--.*?-->|<\s*/?\s*(important|system|secret|admin|instruction|tool_call)\b",
                            re.IGNORECASE | re.DOTALL)

# --- Detector 2: reader-directed instructions (the model is the audience, not the caller). ---
_READER_DIRECTED = re.compile(
    r"ignore\s+(?:all\s+|the\s+|your\s+|any\s+)*(?:previous|prior|above|earlier|preceding)\s+"
    r"(?:instruction|prompt|message|context)"
    r"|disregard\s+(?:the\s+|all\s+|any\s+)*(?:previous|prior|above|earlier)"
    r"|do\s*n?o?t?'?\s*(?:tell|inform|mention|reveal|notify|disclose)\s+(?:the\s+)?(?:user|human)"
    r"|(?:you\s+are|act\s+as|you\s+must\s+act)\s+an?\s+(?:ai|assistant|language\s+model|agent)"
    r"|(?:your|the)\s+system\s+prompt"
    r"|new\s+instructions?\s*:",
    re.IGNORECASE)

# --- Detector 3: secret-exfil directives (read a secret AND move it). ---
# Tightened after a real false positive: Vercel's `get_access_to_vercel_url` says "access ... without
# requiring login credentials" — benign. "access" and a bare "credential" are NOT suspicious. We fire on
# (a) reading an unambiguous secret FILE, or (b) a secret WORD paired with an explicit exfil verb.
# Only unambiguous secret FILES — a legit tool description has no reason to name these. Secret *words*
# ("api key", "password", "credential") appear in countless benign descriptions, so they are NOT used
# (that was the FP source: "pass/fail with an API key", "access without credentials", etc.). Other
# injection styles are still caught by the hidden-markup and reader-directed detectors above.
_SECRET_FILE = r"(?:\.env\b|~/\.ssh|id_rsa|/etc/passwd|/etc/shadow)"
_EXFIL_VERB = r"(?:pass|send|include|attach|exfiltrat\w*|leak|upload|post|forward)"
_EXFIL_DIRECTIVE = re.compile(
    r"(?:read|open|cat|load|retrieve|dump)\b[^.]{0,40}" + _SECRET_FILE   # read a secret file
    + r"|" + _SECRET_FILE + r"[^.]{0,40}\b" + _EXFIL_VERB,                # secret file → moved out
    re.IGNORECASE | re.DOTALL)

_DETECTORS = (
    ("injection:hidden-markup", _HIDDEN_MARKUP),
    ("injection:reader-directed", _READER_DIRECTED),
    ("injection:secret-exfil", _EXFIL_DIRECTIVE),
)

# --- Detector 4: dynamic tool-dispatch (meta-tool defeats tools/list entirely). ---
# A 2026-07-16 dogfooding pass found this is a real, common shape, not a corner case:
# getsentry/sentry-mcp (search_sentry_tools + execute_sentry_tool) and docker/mcp-gateway
# (mcp-find + mcp-exec, ON BY DEFAULT) both collapse dozens-to-hundreds of real tools behind a
# handful of declared ones. A passive tools/list scan structurally cannot see the hidden catalog,
# so this signal exists to say "this scan is incomplete", never "this server is bad" — a clean
# report from a server with this shape is not proof of a clean server.
# Narrow by design (0-FP discipline): fires only on a paired discover+execute name match (both
# tools must be present), or a single execute-shaped tool whose schema takes a free-text
# tool-name/action selector — not on an ordinary "execute_workflow(id)"-style tool with a fixed,
# non-dispatching argument.
_DISCOVER_TOOL_NAME = re.compile(
    r"(?:search|find|discover|list)[-_]?\w*tools?\b|tools?[-_]?(?:search|find|discover|list)\b"
    r"|^mcp[-_]?find$",
    re.IGNORECASE)
_EXEC_TOOL_NAME = re.compile(
    r"(?:execute|exec|invoke|dispatch|call|run)[-_]?\w*tools?\b|tools?[-_]?(?:execute|exec|invoke|dispatch)\b"
    r"|^mcp[-_]?(?:exec|add)$|^code[-_]?mode$",
    re.IGNORECASE)
_DISPATCH_PARAM_NAMES = {"tool", "tool_name", "toolname", "target_tool", "action"}


def detect_dynamic_dispatch(snap: ServerSnapshot) -> list[Finding]:
    """Signal: this server's tools/list likely hides a larger real catalog behind a dynamic
    tool-dispatch pattern (confirmed live on getsentry/sentry-mcp and docker/mcp-gateway)."""
    names = [t.get("name", "?") for t in snap.tools]
    discover = sorted({n for n in names if _DISCOVER_TOOL_NAME.search(n)})
    executor = sorted({n for n in names if _EXEC_TOOL_NAME.search(n)})
    if discover and executor:
        return [Finding(
            tool=", ".join(discover + executor),
            kind="dispatch:dynamic-tool-catalog",
            evidence=(f"{len(names)} tools visible via tools/list, but '{executor[0]}' paired with "
                      f"'{discover[0]}' is the dynamic-dispatch shape (Sentry/Docker mcp-gateway "
                      f"pattern) — the real tool catalog is likely larger and not visible to this scan"))]
    out: list[Finding] = []
    for t in snap.tools:
        n = t.get("name", "?")
        if not _EXEC_TOOL_NAME.search(n):
            continue
        props = ((t.get("inputSchema") or {}).get("properties") or {})
        for pname, pschema in props.items():
            if pname.lower().replace("-", "_") in _DISPATCH_PARAM_NAMES and (pschema or {}).get("type") == "string":
                out.append(Finding(
                    tool=n, kind="dispatch:dynamic-tool-catalog",
                    evidence=(f"'{n}' takes a free-text '{pname}' selector — likely dispatches to "
                              f"tools not visible in this scan's tools/list")))
                break
    return out


@dataclass
class Finding:
    tool: str
    kind: str
    evidence: str            # the matched span — so a human can judge, we never auto-verdict
    confidence: str = "signal"   # never "confirmed"; this layer only signals


def _scan_text(text: str, tool: str) -> list[Finding]:
    out: list[Finding] = []
    for kind, rx in _DETECTORS:
        m = rx.search(text or "")
        if m:
            span = m.group(0).strip()
            out.append(Finding(tool=tool, kind=kind, evidence=span[:120]))
    return out


def detect(snap: ServerSnapshot) -> list[Finding]:
    """Run the BOUNDED detectors over the injection surface: tool AND prompt descriptions.
    (Prompts are model-facing text too — the tool-poisoning surface isn't only tools/list.)"""
    findings: list[Finding] = []
    for t in snap.tools:
        findings.extend(_scan_text(t.get("description") or "", t.get("name", "?")))
    for pr in snap.prompts:
        findings.extend(_scan_text(pr.get("description") or "", f"prompt:{pr.get('name', '?')}"))
    return findings


def detect_shadowing(snaps: list[ServerSnapshot]) -> dict[str, list[Finding]]:
    """CROSS-SERVER signal: a tool name exposed by more than one server. All connected servers share
    one context, so a malicious server can register the same name as a trusted one and shadow it
    (mcp-secret-exfil-threat-model: 'cross-tool shadowing'). Naturally 0-FP — fires only on a genuine
    collision between distinct servers. Returns {server_name -> [Finding]}.
    """
    owners: dict[str, set[str]] = {}
    for s in snaps:
        for t in s.tools:
            owners.setdefault(t.get("name", "?"), set()).add(s.name)
    out: dict[str, list[Finding]] = {}
    for s in snaps:
        for t in s.tools:
            nm = t.get("name", "?")
            others = owners.get(nm, set()) - {s.name}
            if others:
                out.setdefault(s.name, []).append(Finding(
                    tool=nm, kind="shadowing:name-collision",
                    evidence=f"also exposed by: {', '.join(sorted(others))}"))
    return out


def detect_card_mismatch(snap: ServerSnapshot) -> list[Finding]:
    """Signal: the server's public .well-known card UNDER-DECLARES — hides tools it actually exposes.
    A fact-based, 0-FP signal (fires only on a real declared-vs-measured gap). Independent
    measurement catching a self-declaration that doesn't match reality."""
    if not snap.server_card:
        return []
    from .servercard import compare_to_reality
    cmp = compare_to_reality(snap.server_card, [t.get("name", "?") for t in snap.tools])
    out: list[Finding] = []
    if cmp.get("undeclared_tools"):
        u = cmp["undeclared_tools"]
        out.append(Finding(tool="<server-card>", kind="servercard:undeclared-tools",
                           evidence=f"exposes {len(u)} tool(s) absent from its public card: {', '.join(u[:6])}"))
    return out


def as_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    return [{"tool": f.tool, "kind": f.kind, "evidence": f.evidence, "confidence": f.confidence}
            for f in findings]
