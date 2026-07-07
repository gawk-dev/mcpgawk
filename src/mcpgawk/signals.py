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
_SECRET = r"(?:\.env\b|~/\.ssh|id_rsa|/etc/passwd|credential|secret|api[_\s-]?key|password|access[_\s-]?token)"
_EXFIL_DIRECTIVE = re.compile(
    r"(?:read|open|cat|load|access|retrieve|include|attach)\b[^.]{0,50}" + _SECRET
    + r"|" + _SECRET + r"[^.]{0,50}\b(?:pass|send|include|attach|provide|put\s+in|add\s+to|append)\b",
    re.IGNORECASE | re.DOTALL)

_DETECTORS = (
    ("injection:hidden-markup", _HIDDEN_MARKUP),
    ("injection:reader-directed", _READER_DIRECTED),
    ("injection:secret-exfil", _EXFIL_DIRECTIVE),
)


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
